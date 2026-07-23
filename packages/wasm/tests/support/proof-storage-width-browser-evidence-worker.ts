import { openIndexedDbUntrustedStorageAdapter } from '#packages/protocol/src/runtime/indexed-db-untrusted-storage-adapter';
import {
    clearCommonProofExternalMemoryRequest,
    decodeCommonProofExternalMemoryRequest,
    encodeCommonProofExternalMemoryResponseInto,
    type CommonProofExternalMemoryOperation,
    type CommonProofExternalMemoryReadResult,
    type CommonProofExternalMemoryRequest,
} from '#packages/wasm/src/common-proof-worker-runtime/external-memory';
import { createTranscriptCoreKernelLoader } from '#packages/wasm/src/index';
import { resolveCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';
import {
    parseProofStorageWidthBrowserMeasurement,
    parseProofStorageWidthBrowserNativeBinding,
    proofStorageWidthBrowserEvidenceProfile,
    requireProofStorageWidthBrowserNativeMatch,
    serializeProofStorageWidthBrowserMeasurement,
    type ProofStorageWidthBrowserMeasurement,
    type ProofStorageWidthBrowserNativeBinding,
} from '#tests/support/proof-storage-width-browser-evidence';
import { proofStorageWidthProfile } from '#tools/ci/proof-storage-width-evidence';

const statusByteLength = 4;
const resultByteLength = 456;
const resultHashByteLength = 64;
const browserEvidenceResultFormatVersion = 1;
const representativeWidth = 512;
const proofObjectOrdinal = representativeWidth;
const metadataByteLength = 40;
const metadataCreatedState = 1;
const metadataSealedState = 2;
const warmGuardBaselineMilliseconds = 250;
const pollProgress = 1;
const pollStorageRequest = 2;
const pollComplete = 3;
const uniqueQueryCount = 183;
const sourceReplayReadPassCount = 6;
const storageBoundaryBufferByteLength = Number(
    proofStorageWidthProfile.externalMemoryCopiedBufferByteLengthCeiling,
);

type StartMessage = Readonly<{
    command: 'run-proof-storage-width-browser-evidence';
    databaseName: string;
    nativeBinding: unknown;
    wasmSha256Hex: string;
}>;

type EvidenceWasmExports = Readonly<{
    memory: WebAssembly.Memory;
    sealed_lattice_proof_storage_width_browser_begin(
        manifestIdentityPointer: number,
        manifestIdentityByteLength: number,
        statusPointer: number,
    ): number;
    sealed_lattice_proof_storage_width_browser_cancel(
        operationHandle: number,
    ): void;
    sealed_lattice_proof_storage_width_browser_copy_pending_storage_request(
        operationHandle: number,
        outputPointer: number,
        outputByteLength: number,
        statusPointer: number,
    ): number;
    sealed_lattice_proof_storage_width_browser_copy_result(
        operationHandle: number,
        outputPointer: number,
        outputByteLength: number,
        statusPointer: number,
    ): number;
    sealed_lattice_proof_storage_width_browser_pending_storage_request_byte_length(
        operationHandle: number,
        statusPointer: number,
    ): number;
    sealed_lattice_proof_storage_width_browser_poll(
        operationHandle: number,
        statusPointer: number,
    ): number;
    sealed_lattice_proof_storage_width_browser_release(
        operationHandle: number,
    ): void;
    sealed_lattice_proof_storage_width_browser_result_byte_length(
        operationHandle: number,
        statusPointer: number,
    ): number;
    sealed_lattice_proof_storage_width_browser_supply_storage_response(
        operationHandle: number,
        inputPointer: number,
        inputByteLength: number,
        statusPointer: number,
    ): number;
}>;

type RustEvidenceResult = Readonly<{
    absorbedLeafValueCount: bigint;
    artifactShake256Hex: string;
    baseRootShake256Hex: string;
    canonicalArtifactByteLength: bigint;
    canonicalArtifactNonleafRangeChunkCount: bigint;
    canonicalArtifactPostleafRangeChunkCount: bigint;
    canonicalArtifactPreleafRangeChunkCount: bigint;
    custodyCleanupCompleted: boolean;
    externalCommittedTransactionCount: bigint;
    externalReadByteLength: bigint;
    externalWrittenByteLength: bigint;
    inputIdentityShake256Hex: string;
    ldeTransformCount: bigint;
    localRecordSealInvocationCount: bigint;
    manifestIdentityShake256Hex: string;
    openedLeafElementByteLength: bigint;
    openedLeafRangeChunkCount: bigint;
    openedValueCount: bigint;
    physicalObjectPeak: bigint;
    publicBaseLeafByteLength: bigint;
    publicBaseLeafColumnCount: 512;
    queriedLeafPayloadByteLength: bigint;
    recomputedCanonicalArtifactByteLength: bigint;
    sealedSecretPlaintextByteLength: bigint;
    sourceCommittedTransactionCount: bigint;
    sourceObjectSealTransactionCount: bigint;
    sourceReplayByteLength: bigint;
    storedScratchPeakByteLength: bigint;
    proofObjectSealTransactionCount: bigint;
}>;

type TimingAccumulator = {
    arithmeticNanoseconds: bigint;
    externalStorageWaitNanoseconds: bigint;
    maximumArithmeticSliceNanoseconds: bigint;
    workerYieldCount: bigint;
    workerYieldNanoseconds: bigint;
};

type StoredRange = Readonly<{
    byteLength: number;
    key: string;
    offset: bigint;
}>;

type StoredObject = {
    appendedByteLength: bigint;
    exactByteLength: bigint;
    metadataBytes: Uint8Array;
    metadataKey: string;
    objectKind: 'canonical-proof-artifact' | 'replay-source';
    objectOrdinal: number;
    ranges: StoredRange[];
    readRanges: Array<Readonly<{ byteLength: number; offset: bigint }>>;
    sealed: boolean;
};

type StorageAccounting = {
    copiedBufferPeakByteLength: bigint;
    currentStoredByteLength: bigint;
    externalCommittedCreateTransactionCount: bigint;
    externalCommittedDeleteTransactionCount: bigint;
    externalCommittedReadTransactionCount: bigint;
    externalCommittedSealTransactionCount: bigint;
    externalCommittedWriteTransactionCount: bigint;
    externalReadByteLength: bigint;
    externalWrittenByteLength: bigint;
    physicalObjectPeak: bigint;
    proofArtifactWrittenByteLength: bigint;
    proofObjectSealTransactionCount: bigint;
    providerCleanupInspectionTransactionCount: bigint;
    providerDataRecordPeak: bigint;
    providerMetadataRecordPeak: bigint;
    providerMetadataWrittenByteLength: bigint;
    providerMutationTransactionCount: bigint;
    providerReadTransactionCount: bigint;
    providerRecordPeak: bigint;
    replaySourceWrittenByteLength: bigint;
    sourceCommittedTransactionCount: bigint;
    sourceObjectSealTransactionCount: bigint;
    storedScratchPeakByteLength: bigint;
};

const workerScope = globalThis as unknown as Readonly<{
    addEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void;
    postMessage(message: unknown): void;
}>;

const parseStartMessage = (value: unknown): StartMessage => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError('The browser evidence start message is malformed.');
    }
    const record = value as Readonly<Record<string, unknown>>;
    if (
        record.command !== 'run-proof-storage-width-browser-evidence' ||
        typeof record.databaseName !== 'string' ||
        record.databaseName.length === 0 ||
        record.databaseName.length > 256 ||
        typeof record.wasmSha256Hex !== 'string' ||
        !/^[0-9a-f]{64}$/u.test(record.wasmSha256Hex)
    ) {
        throw new TypeError('The browser evidence start message is invalid.');
    }
    return Object.freeze({
        command: 'run-proof-storage-width-browser-evidence',
        databaseName: record.databaseName,
        nativeBinding: record.nativeBinding,
        wasmSha256Hex: record.wasmSha256Hex,
    });
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const hexToBytes = (hex: string): Uint8Array<ArrayBuffer> => {
    if (!/^[0-9a-f]+$/u.test(hex) || hex.length % 2 !== 0) {
        throw new TypeError(
            'A browser evidence hexadecimal value is malformed.',
        );
    }
    const bytes = new Uint8Array(hex.length / 2);
    for (let offset = 0; offset < bytes.byteLength; offset += 1) {
        bytes[offset] = Number.parseInt(
            hex.slice(offset * 2, offset * 2 + 2),
            16,
        );
    }
    return bytes;
};

const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    for (let index = 0; index < left.byteLength; index += 1) {
        if (left[index] !== right[index]) {
            return false;
        }
    }
    return true;
};

const millisecondsToNanoseconds = (milliseconds: number): bigint => {
    if (!Number.isFinite(milliseconds) || milliseconds < 0) {
        throw new RangeError('A browser evidence duration is invalid.');
    }
    return BigInt(Math.round(milliseconds * 1_000_000));
};

const measureSynchronousArithmetic = <Value>(
    timing: TimingAccumulator,
    operation: () => Value,
): Value => {
    const started = performance.now();
    try {
        return operation();
    } finally {
        const elapsed = millisecondsToNanoseconds(performance.now() - started);
        timing.arithmeticNanoseconds += elapsed;
        timing.maximumArithmeticSliceNanoseconds =
            timing.maximumArithmeticSliceNanoseconds > elapsed
                ? timing.maximumArithmeticSliceNanoseconds
                : elapsed;
    }
};

const measureStorageWait = async <Value>(
    timing: TimingAccumulator,
    operation: () => Promise<Value>,
): Promise<Value> => {
    const started = performance.now();
    try {
        return await operation();
    } finally {
        timing.externalStorageWaitNanoseconds += millisecondsToNanoseconds(
            performance.now() - started,
        );
    }
};

const delay = (milliseconds: number): Promise<void> =>
    new Promise((resolve) => setTimeout(resolve, milliseconds));

const yieldBrowserTurn = async (timing: TimingAccumulator): Promise<void> => {
    const started = performance.now();
    await delay(0);
    timing.workerYieldCount += 1n;
    timing.workerYieldNanoseconds += millisecondsToNanoseconds(
        performance.now() - started,
    );
};

const deleteDatabase = (
    indexedDbFactory: IDBFactory,
    databaseName: string,
): Promise<void> =>
    new Promise((resolve, reject) => {
        const request = indexedDbFactory.deleteDatabase(databaseName);
        request.addEventListener('success', () => resolve(), { once: true });
        request.addEventListener(
            'error',
            () =>
                reject(
                    request.error ?? new Error('IndexedDB deletion failed.'),
                ),
            { once: true },
        );
        request.addEventListener(
            'blocked',
            () => reject(new Error('IndexedDB deletion was blocked.')),
            { once: true },
        );
    });

const resolveEvidenceExports = (value: unknown): EvidenceWasmExports => {
    if (typeof value !== 'object' || value === null) {
        throw new Error('The release WebAssembly export table is unavailable.');
    }
    const exportNames = [
        'sealed_lattice_proof_storage_width_browser_begin',
        'sealed_lattice_proof_storage_width_browser_cancel',
        'sealed_lattice_proof_storage_width_browser_copy_pending_storage_request',
        'sealed_lattice_proof_storage_width_browser_copy_result',
        'sealed_lattice_proof_storage_width_browser_pending_storage_request_byte_length',
        'sealed_lattice_proof_storage_width_browser_poll',
        'sealed_lattice_proof_storage_width_browser_release',
        'sealed_lattice_proof_storage_width_browser_result_byte_length',
        'sealed_lattice_proof_storage_width_browser_supply_storage_response',
    ] as const;
    for (const exportName of exportNames) {
        if (
            typeof (value as Readonly<Record<string, unknown>>)[exportName] !==
            'function'
        ) {
            throw new Error(
                `The release WebAssembly module is missing ${exportName}.`,
            );
        }
    }
    return value as unknown as EvidenceWasmExports;
};

const parseRustEvidenceResult = (bytes: Uint8Array): RustEvidenceResult => {
    if (bytes.byteLength !== resultByteLength) {
        throw new Error(
            'The release WebAssembly browser result has the wrong length.',
        );
    }
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    if (
        view.getUint32(0, true) !== browserEvidenceResultFormatVersion ||
        view.getUint32(4, true) !== representativeWidth
    ) {
        throw new Error(
            'The release WebAssembly browser result header is invalid.',
        );
    }
    const manifestOffset = 8;
    const inputOffset = manifestOffset + resultHashByteLength;
    const rootOffset = inputOffset + resultHashByteLength;
    const artifactOffset = rootOffset + resultHashByteLength;
    let counterOffset = artifactOffset + resultHashByteLength;
    const nextCounter = (): bigint => {
        const value = view.getBigUint64(counterOffset, true);
        counterOffset += 8;
        return value;
    };
    const canonicalArtifactByteLength = nextCounter();
    const recomputedCanonicalArtifactByteLength = nextCounter();
    const sourceReplayByteLength = nextCounter();
    const queriedLeafPayloadByteLength = nextCounter();
    const publicBaseLeafByteLength = nextCounter();
    const openedLeafElementByteLength = nextCounter();
    const openedLeafRangeChunkCount = nextCounter();
    const canonicalArtifactPreleafRangeChunkCount = nextCounter();
    const canonicalArtifactPostleafRangeChunkCount = nextCounter();
    const canonicalArtifactNonleafRangeChunkCount = nextCounter();
    const physicalObjectPeak = nextCounter();
    const storedScratchPeakByteLength = nextCounter();
    const ldeTransformCount = nextCounter();
    const absorbedLeafValueCount = nextCounter();
    const openedValueCount = nextCounter();
    const externalReadByteLength = nextCounter();
    const externalWrittenByteLength = nextCounter();
    const externalCommittedTransactionCount = nextCounter();
    const sourceCommittedTransactionCount = nextCounter();
    const sourceObjectSealTransactionCount = nextCounter();
    const proofObjectSealTransactionCount = nextCounter();
    const localRecordSealInvocationCount = nextCounter();
    const sealedSecretPlaintextByteLength = nextCounter();
    const custodyCleanupCompleted = nextCounter();
    if (counterOffset !== resultByteLength || custodyCleanupCompleted !== 1n) {
        throw new Error(
            'The release WebAssembly browser result accounting is malformed.',
        );
    }
    return Object.freeze({
        absorbedLeafValueCount,
        artifactShake256Hex: bytesToHex(
            bytes.subarray(
                artifactOffset,
                artifactOffset + resultHashByteLength,
            ),
        ),
        baseRootShake256Hex: bytesToHex(
            bytes.subarray(rootOffset, rootOffset + resultHashByteLength),
        ),
        canonicalArtifactByteLength,
        canonicalArtifactNonleafRangeChunkCount,
        canonicalArtifactPostleafRangeChunkCount,
        canonicalArtifactPreleafRangeChunkCount,
        custodyCleanupCompleted: true,
        externalCommittedTransactionCount,
        externalReadByteLength,
        externalWrittenByteLength,
        inputIdentityShake256Hex: bytesToHex(
            bytes.subarray(inputOffset, inputOffset + resultHashByteLength),
        ),
        ldeTransformCount,
        localRecordSealInvocationCount,
        manifestIdentityShake256Hex: bytesToHex(
            bytes.subarray(
                manifestOffset,
                manifestOffset + resultHashByteLength,
            ),
        ),
        openedLeafElementByteLength,
        openedLeafRangeChunkCount,
        openedValueCount,
        physicalObjectPeak,
        proofObjectSealTransactionCount,
        publicBaseLeafByteLength,
        publicBaseLeafColumnCount: 512,
        queriedLeafPayloadByteLength,
        recomputedCanonicalArtifactByteLength,
        sealedSecretPlaintextByteLength,
        sourceCommittedTransactionCount,
        sourceObjectSealTransactionCount,
        sourceReplayByteLength,
        storedScratchPeakByteLength,
    });
};

const objectKind = (objectOrdinal: number): StoredObject['objectKind'] => {
    if (objectOrdinal >= 0 && objectOrdinal < representativeWidth) {
        return 'replay-source';
    }
    if (objectOrdinal === proofObjectOrdinal) {
        return 'canonical-proof-artifact';
    }
    throw new Error(
        'The browser evidence request names an unknown logical object.',
    );
};

const objectPrefix = (databaseName: string, objectOrdinal: number): string =>
    `${databaseName}/objects/${objectOrdinal.toString().padStart(4, '0')}`;

const encodeMetadata = (input: {
    appendedByteLength: bigint;
    exactByteLength: bigint;
    objectOrdinal: number;
    rangeCount: number;
    state: number;
}): Uint8Array<ArrayBuffer> => {
    const bytes = new Uint8Array(metadataByteLength);
    bytes.set(new TextEncoder().encode('SLWOBJ01'), 0);
    const view = new DataView(bytes.buffer);
    view.setUint32(8, input.state, true);
    view.setUint32(12, input.objectOrdinal, true);
    view.setBigUint64(16, input.exactByteLength, true);
    view.setBigUint64(24, input.appendedByteLength, true);
    view.setUint32(32, input.rangeCount, true);
    view.setUint32(36, 0, true);
    return bytes;
};

const updateProviderPeaks = (
    storage: StorageAccounting,
    objects: ReadonlyMap<number, StoredObject>,
): void => {
    const metadataRecordCount = BigInt(objects.size);
    const dataRecordCount = BigInt(
        [...objects.values()].reduce(
            (recordCount, object) => recordCount + object.ranges.length,
            0,
        ),
    );
    const recordCount = metadataRecordCount + dataRecordCount;
    storage.providerMetadataRecordPeak =
        storage.providerMetadataRecordPeak > metadataRecordCount
            ? storage.providerMetadataRecordPeak
            : metadataRecordCount;
    storage.providerDataRecordPeak =
        storage.providerDataRecordPeak > dataRecordCount
            ? storage.providerDataRecordPeak
            : dataRecordCount;
    storage.providerRecordPeak =
        storage.providerRecordPeak > recordCount
            ? storage.providerRecordPeak
            : recordCount;
    storage.physicalObjectPeak =
        storage.physicalObjectPeak > metadataRecordCount
            ? storage.physicalObjectPeak
            : metadataRecordCount;
    storage.storedScratchPeakByteLength =
        storage.storedScratchPeakByteLength > storage.currentStoredByteLength
            ? storage.storedScratchPeakByteLength
            : storage.currentStoredByteLength;
};

const expectedChunkLengths = (exactByteLength: bigint): readonly number[] => {
    const maximum = Number(
        proofStorageWidthBrowserEvidenceProfile.maximumTransactionPayloadByteLength,
    );
    const lengths: number[] = [];
    let remaining = exactByteLength;
    while (remaining > 0n) {
        const length = Number(
            remaining > BigInt(maximum) ? BigInt(maximum) : remaining,
        );
        lengths.push(length);
        remaining -= BigInt(length);
    }
    return lengths;
};

const validateRangeSequence = (
    actual: readonly StoredRange[],
    expectedLengths: readonly number[],
    description: string,
): void => {
    if (
        actual.length !== expectedLengths.length ||
        actual.some(
            (range, index) => range.byteLength !== expectedLengths[index],
        )
    ) {
        throw new Error(
            `${description} does not preserve the canonical range chunks.`,
        );
    }
};

const validateArtifactRanges = (
    object: StoredObject,
    nativeBinding: ProofStorageWidthBrowserNativeBinding,
): void => {
    const preleafCount = Number(
        nativeBinding.canonicalArtifactPreleafRangeChunkCount,
    );
    const postleafCount = Number(
        nativeBinding.canonicalArtifactPostleafRangeChunkCount,
    );
    const leafChunkLengths = expectedChunkLengths(
        nativeBinding.openedLeafElementByteLength,
    );
    const expectedLeafCount = leafChunkLengths.length * uniqueQueryCount;
    if (
        !Number.isSafeInteger(preleafCount) ||
        !Number.isSafeInteger(postleafCount) ||
        BigInt(expectedLeafCount) !== nativeBinding.openedLeafRangeChunkCount ||
        object.ranges.length !==
            preleafCount + expectedLeafCount + postleafCount
    ) {
        throw new Error(
            'The canonical proof artifact range catalog is inconsistent.',
        );
    }
    const preleafRanges = object.ranges.slice(0, preleafCount);
    const leafRanges = object.ranges.slice(
        preleafCount,
        preleafCount + expectedLeafCount,
    );
    const postleafRanges = object.ranges.slice(
        preleafCount + expectedLeafCount,
    );
    const maximumChunkByteLength = Number(
        proofStorageWidthBrowserEvidenceProfile.maximumTransactionPayloadByteLength,
    );
    for (const [description, ranges] of [
        ['preleaf', preleafRanges],
        ['postleaf', postleafRanges],
    ] as const) {
        if (
            ranges.some(
                (range, rangeIndex) =>
                    range.byteLength <= 0 ||
                    range.byteLength > maximumChunkByteLength ||
                    (rangeIndex + 1 < ranges.length &&
                        range.byteLength !== maximumChunkByteLength),
            )
        ) {
            throw new Error(
                `The canonical proof ${description} range is not chunked canonically.`,
            );
        }
    }
    for (let queryIndex = 0; queryIndex < uniqueQueryCount; queryIndex += 1) {
        validateRangeSequence(
            leafRanges.slice(
                queryIndex * leafChunkLengths.length,
                (queryIndex + 1) * leafChunkLengths.length,
            ),
            leafChunkLengths,
            `Canonical proof opened leaf ${String(queryIndex)}`,
        );
    }
};

const validateCompletedReads = (
    object: StoredObject,
    nativeBinding: ProofStorageWidthBrowserNativeBinding,
): void => {
    const expectedReadPasses =
        object.objectKind === 'replay-source' ? sourceReplayReadPassCount : 1;
    if (
        object.readRanges.length !==
        object.ranges.length * expectedReadPasses
    ) {
        throw new Error(
            'The browser evidence object has incomplete fresh-verifier reads.',
        );
    }
    for (let pass = 0; pass < expectedReadPasses; pass += 1) {
        for (const [rangeIndex, range] of object.ranges.entries()) {
            const readRange =
                object.readRanges[pass * object.ranges.length + rangeIndex];
            if (
                readRange === undefined ||
                readRange.offset !== range.offset ||
                readRange.byteLength !== range.byteLength
            ) {
                throw new Error(
                    'The browser evidence read transaction boundaries changed.',
                );
            }
        }
    }
    if (object.objectKind === 'canonical-proof-artifact') {
        validateArtifactRanges(object, nativeBinding);
    }
};

const requestObjectKind = (
    request: CommonProofExternalMemoryRequest,
): StoredObject['objectKind'] => {
    const kinds = new Set(
        request.operations.map((operation) =>
            objectKind(operation.objectOrdinal),
        ),
    );
    if (kinds.size !== 1) {
        throw new Error(
            'A browser evidence transaction mixes source and proof objects.',
        );
    }
    const kind = kinds.values().next().value;
    if (kind === undefined) {
        throw new Error(
            'A browser evidence transaction has no logical object kind.',
        );
    }
    return kind;
};

const assembleRead = async (input: {
    adapter: Awaited<ReturnType<typeof openIndexedDbUntrustedStorageAdapter>>;
    object: StoredObject;
    operation: Extract<
        CommonProofExternalMemoryOperation,
        { operationKind: 'read' }
    >;
    storage: StorageAccounting;
}): Promise<Uint8Array<ArrayBuffer>> => {
    const persistedMetadata = await input.adapter.read(
        input.object.metadataKey,
    );
    input.storage.providerReadTransactionCount += 1n;
    if (
        persistedMetadata === undefined ||
        !bytesEqual(persistedMetadata, input.object.metadataBytes)
    ) {
        throw new Error('IndexedDB did not retain the sealed object metadata.');
    }
    const readEnd = input.operation.offset + BigInt(input.operation.byteLength);
    if (readEnd > input.object.exactByteLength) {
        throw new Error(
            'The browser evidence requested an out-of-bounds object range.',
        );
    }
    const output = new Uint8Array(input.operation.byteLength);
    let copiedByteLength = 0;
    for (const range of input.object.ranges) {
        const rangeEnd = range.offset + BigInt(range.byteLength);
        const overlapStart =
            range.offset > input.operation.offset
                ? range.offset
                : input.operation.offset;
        const overlapEnd = rangeEnd < readEnd ? rangeEnd : readEnd;
        if (overlapStart >= overlapEnd) {
            continue;
        }
        const persistedRange = await input.adapter.read(range.key);
        input.storage.providerReadTransactionCount += 1n;
        if (
            persistedRange === undefined ||
            persistedRange.byteLength !== range.byteLength
        ) {
            throw new Error(
                'IndexedDB returned a missing or malformed object range.',
            );
        }
        const sourceOffset = Number(overlapStart - range.offset);
        const targetOffset = Number(overlapStart - input.operation.offset);
        const overlapByteLength = Number(overlapEnd - overlapStart);
        output.set(
            persistedRange.subarray(
                sourceOffset,
                sourceOffset + overlapByteLength,
            ),
            targetOffset,
        );
        copiedByteLength += overlapByteLength;
    }
    if (copiedByteLength !== output.byteLength) {
        output.fill(0);
        throw new Error(
            'IndexedDB ranges do not completely cover the requested read.',
        );
    }
    input.object.readRanges.push({
        byteLength: input.operation.byteLength,
        offset: input.operation.offset,
    });
    return output;
};

const executeStorageRequest = async (input: {
    adapter: Awaited<ReturnType<typeof openIndexedDbUntrustedStorageAdapter>>;
    databaseName: string;
    nativeBinding: ProofStorageWidthBrowserNativeBinding;
    objects: Map<number, StoredObject>;
    request: CommonProofExternalMemoryRequest;
    storage: StorageAccounting;
}): Promise<readonly CommonProofExternalMemoryReadResult[]> => {
    if (
        input.request.maximumPayloadByteLength !==
        proofStorageWidthBrowserEvidenceProfile.maximumTransactionPayloadByteLength
    ) {
        throw new Error(
            'The Rust storage request changed the fixed payload bound.',
        );
    }
    const firstOperation = input.request.operations[0];
    if (firstOperation === undefined) {
        throw new Error('The Rust storage request contains no operation.');
    }
    const kind = requestObjectKind(input.request);
    const readResults: CommonProofExternalMemoryReadResult[] = [];
    switch (firstOperation.operationKind) {
        case 'create': {
            if (input.request.operations.length !== 1) {
                throw new Error(
                    'A create transaction contains multiple operations.',
                );
            }
            if (
                firstOperation.protection !== 'public-integrity' ||
                input.objects.has(firstOperation.objectOrdinal)
            ) {
                throw new Error(
                    'The browser evidence refused a secret or duplicate object.',
                );
            }
            const createdKind = objectKind(firstOperation.objectOrdinal);
            const expectedByteLength =
                createdKind === 'replay-source'
                    ? input.nativeBinding.sourceReplayByteLength /
                      BigInt(representativeWidth)
                    : input.nativeBinding.canonicalArtifactByteLength;
            if (firstOperation.exactByteLength !== expectedByteLength) {
                throw new Error(
                    'The browser evidence object has the wrong exact length.',
                );
            }
            const prefix = objectPrefix(
                input.databaseName,
                firstOperation.objectOrdinal,
            );
            const metadataBytes = encodeMetadata({
                appendedByteLength: 0n,
                exactByteLength: firstOperation.exactByteLength,
                objectOrdinal: firstOperation.objectOrdinal,
                rangeCount: 0,
                state: metadataCreatedState,
            });
            const metadataKey = `${prefix}/metadata`;
            const committed = await input.adapter.applyAtomicMutation({
                deletes: [],
                expectedValues: [{ key: metadataKey, value: undefined }],
                writes: [{ key: metadataKey, value: metadataBytes }],
            });
            input.storage.providerMutationTransactionCount += 1n;
            if (!committed) {
                throw new Error(
                    'IndexedDB refused the object-create transaction.',
                );
            }
            input.storage.providerMetadataWrittenByteLength += BigInt(
                metadataBytes.byteLength,
            );
            input.objects.set(firstOperation.objectOrdinal, {
                appendedByteLength: 0n,
                exactByteLength: firstOperation.exactByteLength,
                metadataBytes,
                metadataKey,
                objectKind: createdKind,
                objectOrdinal: firstOperation.objectOrdinal,
                ranges: [],
                readRanges: [],
                sealed: false,
            });
            input.storage.externalCommittedCreateTransactionCount += 1n;
            break;
        }
        case 'append': {
            if (input.request.operations.length !== 1) {
                throw new Error(
                    'An append transaction contains multiple operations.',
                );
            }
            const object = input.objects.get(firstOperation.objectOrdinal);
            if (
                object === undefined ||
                object.sealed ||
                firstOperation.expectedOffset !== object.appendedByteLength ||
                object.appendedByteLength +
                    BigInt(firstOperation.bytes.byteLength) >
                    object.exactByteLength
            ) {
                throw new Error(
                    'The browser evidence append violates object lifecycle.',
                );
            }
            const rangeOrdinal = object.ranges.length;
            const rangeKey = `${objectPrefix(
                input.databaseName,
                object.objectOrdinal,
            )}/ranges/${rangeOrdinal.toString().padStart(8, '0')}`;
            const nextAppendedByteLength =
                object.appendedByteLength +
                BigInt(firstOperation.bytes.byteLength);
            const nextMetadata = encodeMetadata({
                appendedByteLength: nextAppendedByteLength,
                exactByteLength: object.exactByteLength,
                objectOrdinal: object.objectOrdinal,
                rangeCount: rangeOrdinal + 1,
                state: metadataCreatedState,
            });
            const committed = await input.adapter.applyAtomicMutation({
                deletes: [],
                expectedValues: [
                    { key: object.metadataKey, value: object.metadataBytes },
                    { key: rangeKey, value: undefined },
                ],
                writes: [
                    { key: rangeKey, value: firstOperation.bytes },
                    { key: object.metadataKey, value: nextMetadata },
                ],
            });
            input.storage.providerMutationTransactionCount += 1n;
            if (!committed) {
                throw new Error(
                    'IndexedDB refused the object-append transaction.',
                );
            }
            object.ranges.push({
                byteLength: firstOperation.bytes.byteLength,
                key: rangeKey,
                offset: firstOperation.expectedOffset,
            });
            object.appendedByteLength = nextAppendedByteLength;
            object.metadataBytes = nextMetadata;
            input.storage.currentStoredByteLength += BigInt(
                firstOperation.bytes.byteLength,
            );
            input.storage.externalWrittenByteLength += BigInt(
                firstOperation.bytes.byteLength,
            );
            input.storage.providerMetadataWrittenByteLength += BigInt(
                nextMetadata.byteLength,
            );
            if (object.objectKind === 'replay-source') {
                input.storage.replaySourceWrittenByteLength += BigInt(
                    firstOperation.bytes.byteLength,
                );
            } else {
                input.storage.proofArtifactWrittenByteLength += BigInt(
                    firstOperation.bytes.byteLength,
                );
            }
            input.storage.externalCommittedWriteTransactionCount += 1n;
            break;
        }
        case 'seal': {
            if (input.request.operations.length !== 1) {
                throw new Error(
                    'A seal transaction contains multiple operations.',
                );
            }
            const object = input.objects.get(firstOperation.objectOrdinal);
            if (
                object === undefined ||
                object.sealed ||
                object.appendedByteLength !== object.exactByteLength
            ) {
                throw new Error(
                    'The browser evidence seal violates object lifecycle.',
                );
            }
            if (object.objectKind === 'replay-source') {
                validateRangeSequence(
                    object.ranges,
                    expectedChunkLengths(object.exactByteLength),
                    `Replay source ${String(object.objectOrdinal)}`,
                );
            } else {
                validateArtifactRanges(object, input.nativeBinding);
            }
            const sealedMetadata = encodeMetadata({
                appendedByteLength: object.appendedByteLength,
                exactByteLength: object.exactByteLength,
                objectOrdinal: object.objectOrdinal,
                rangeCount: object.ranges.length,
                state: metadataSealedState,
            });
            const committed = await input.adapter.applyAtomicMutation({
                deletes: [],
                expectedValues: [
                    { key: object.metadataKey, value: object.metadataBytes },
                ],
                writes: [{ key: object.metadataKey, value: sealedMetadata }],
            });
            input.storage.providerMutationTransactionCount += 1n;
            if (!committed) {
                throw new Error(
                    'IndexedDB refused the object-seal transaction.',
                );
            }
            object.metadataBytes = sealedMetadata;
            object.sealed = true;
            input.storage.providerMetadataWrittenByteLength += BigInt(
                sealedMetadata.byteLength,
            );
            input.storage.externalCommittedSealTransactionCount += 1n;
            if (object.objectKind === 'replay-source') {
                input.storage.sourceObjectSealTransactionCount += 1n;
            } else {
                input.storage.proofObjectSealTransactionCount += 1n;
            }
            break;
        }
        case 'read': {
            if (input.request.operations.length !== 1) {
                throw new Error(
                    'A read transaction contains multiple operations.',
                );
            }
            const object = input.objects.get(firstOperation.objectOrdinal);
            if (object === undefined || !object.sealed) {
                throw new Error(
                    'The browser evidence refused a pre-seal object read.',
                );
            }
            const bytes = await assembleRead({
                adapter: input.adapter,
                object,
                operation: firstOperation,
                storage: input.storage,
            });
            readResults.push({
                bytes,
                objectOrdinal: firstOperation.objectOrdinal,
                offset: firstOperation.offset,
                operationIndex: firstOperation.operationIndex,
            });
            input.storage.externalReadByteLength += BigInt(bytes.byteLength);
            input.storage.externalCommittedReadTransactionCount += 1n;
            break;
        }
        case 'delete': {
            if (
                input.request.operations.some(
                    (operation) => operation.operationKind !== 'delete',
                )
            ) {
                throw new Error('A delete transaction mixes operation kinds.');
            }
            const deletingObjects = input.request.operations.map(
                (operation) => {
                    const object = input.objects.get(operation.objectOrdinal);
                    if (object === undefined || !object.sealed) {
                        throw new Error(
                            'The browser evidence delete names an unsealed object.',
                        );
                    }
                    validateCompletedReads(object, input.nativeBinding);
                    return object;
                },
            );
            const committed = await input.adapter.applyAtomicMutation({
                deletes: deletingObjects.flatMap((object) => [
                    object.metadataKey,
                    ...object.ranges.map((range) => range.key),
                ]),
                expectedValues: deletingObjects.map((object) => ({
                    key: object.metadataKey,
                    value: object.metadataBytes,
                })),
                writes: [],
            });
            input.storage.providerMutationTransactionCount += 1n;
            if (!committed) {
                throw new Error(
                    'IndexedDB refused the object-delete transaction.',
                );
            }
            for (const object of deletingObjects) {
                input.objects.delete(object.objectOrdinal);
                input.storage.currentStoredByteLength -= object.exactByteLength;
            }
            input.storage.externalCommittedDeleteTransactionCount += 1n;
            break;
        }
    }
    if (kind === 'replay-source') {
        input.storage.sourceCommittedTransactionCount += 1n;
    }
    updateProviderPeaks(input.storage, input.objects);
    return readResults;
};

const runBrowserEvidence = async (
    message: StartMessage,
): Promise<ProofStorageWidthBrowserMeasurement> => {
    const nativeBinding = parseProofStorageWidthBrowserNativeBinding(
        message.nativeBinding,
    );
    if (
        !Number.isSafeInteger(storageBoundaryBufferByteLength) ||
        storageBoundaryBufferByteLength <= 0 ||
        BigInt(storageBoundaryBufferByteLength) !==
            proofStorageWidthProfile.externalMemoryCopiedBufferByteLengthCeiling ||
        BigInt(storageBoundaryBufferByteLength) >
            proofStorageWidthBrowserEvidenceProfile.maximumCopiedBufferByteLength
    ) {
        throw new Error(
            'The browser evidence storage boundary buffer is not exact or bounded.',
        );
    }
    const indexedDbFactory = globalThis.indexedDB;
    const keyRangeFactory = globalThis.IDBKeyRange;
    if (indexedDbFactory === undefined || keyRangeFactory === undefined) {
        throw new Error('The desktop browser does not expose IndexedDB.');
    }
    const kernel = await createTranscriptCoreKernelLoader(
        new URL('../../dist/sealed-lattice-kernel.wasm', import.meta.url),
        { expectedKernelSha256Hex: message.wasmSha256Hex },
    )();
    const context = resolveCommonProofKernelContext(kernel);
    if (context === undefined) {
        throw new Error(
            'The release WebAssembly common-proof context is missing.',
        );
    }
    const wasmExports = resolveEvidenceExports(context.wasmExports);
    let adapter: Awaited<
        ReturnType<typeof openIndexedDbUntrustedStorageAdapter>
    >;
    try {
        adapter = await openIndexedDbUntrustedStorageAdapter({
            databaseName: message.databaseName,
            indexedDbFactory,
            keyRangeFactory,
        });
    } catch (openFailure) {
        try {
            await deleteDatabase(indexedDbFactory, message.databaseName);
        } catch (cleanupFailure) {
            throw Object.assign(
                new Error(
                    'Opening and removing the browser evidence database both failed.',
                ),
                {
                    causes: Object.freeze([openFailure, cleanupFailure]),
                },
            );
        }
        throw openFailure;
    }
    const timing: TimingAccumulator = {
        arithmeticNanoseconds: 0n,
        externalStorageWaitNanoseconds: 0n,
        maximumArithmeticSliceNanoseconds: 0n,
        workerYieldCount: 0n,
        workerYieldNanoseconds: 0n,
    };
    const storage: StorageAccounting = {
        copiedBufferPeakByteLength: 0n,
        currentStoredByteLength: 0n,
        externalCommittedCreateTransactionCount: 0n,
        externalCommittedDeleteTransactionCount: 0n,
        externalCommittedReadTransactionCount: 0n,
        externalCommittedSealTransactionCount: 0n,
        externalCommittedWriteTransactionCount: 0n,
        externalReadByteLength: 0n,
        externalWrittenByteLength: 0n,
        physicalObjectPeak: 0n,
        proofArtifactWrittenByteLength: 0n,
        proofObjectSealTransactionCount: 0n,
        providerCleanupInspectionTransactionCount: 0n,
        providerDataRecordPeak: 0n,
        providerMetadataRecordPeak: 0n,
        providerMetadataWrittenByteLength: 0n,
        providerMutationTransactionCount: 0n,
        providerReadTransactionCount: 0n,
        providerRecordPeak: 0n,
        replaySourceWrittenByteLength: 0n,
        sourceCommittedTransactionCount: 0n,
        sourceObjectSealTransactionCount: 0n,
        storedScratchPeakByteLength: 0n,
    };
    const objects = new Map<number, StoredObject>();
    let operationHandle = 0;
    let statusPointer = 0;
    let resultPointer = 0;
    let storageBoundaryPointer = 0;
    const encodedRequestBuffer = new Uint8Array(
        storageBoundaryBufferByteLength,
    );
    const encodedResponseBuffer = new Uint8Array(
        storageBoundaryBufferByteLength,
    );
    let operationReleased = false;
    let primaryFailure: unknown;
    let completedMeasurement: ProofStorageWidthBrowserMeasurement | undefined;
    try {
        const initialKeys = await adapter.listKeys('');
        storage.providerCleanupInspectionTransactionCount += 1n;
        if (initialKeys.length !== 0) {
            throw new Error(
                'IndexedDB was not empty before browser evidence started.',
            );
        }
        statusPointer = context.allocate(statusByteLength);
        resultPointer = context.allocate(resultByteLength);
        storageBoundaryPointer = context.allocate(
            storageBoundaryBufferByteLength,
        );
        if (
            statusPointer === 0 ||
            resultPointer === 0 ||
            storageBoundaryPointer === 0
        ) {
            throw new Error(
                'The release WebAssembly allocator refused evidence buffers.',
            );
        }
        const resetStatus = (): void => {
            new DataView(context.memory.buffer).setUint32(
                statusPointer,
                0,
                true,
            );
        };
        const checkedCall = (
            operationName: string,
            operation: () => number,
        ): number => {
            resetStatus();
            const result = operation();
            const status = new DataView(context.memory.buffer).getUint32(
                statusPointer,
                true,
            );
            if (status !== 0) {
                throw new Error(
                    `The release WebAssembly ${operationName} refused with status ${String(status)}.`,
                );
            }
            return result;
        };
        const copyFromWasm = (
            pointer: number,
            byteLength: number,
        ): Uint8Array => {
            const copy = new Uint8Array(byteLength);
            copy.set(
                new Uint8Array(context.memory.buffer, pointer, byteLength),
            );
            storage.copiedBufferPeakByteLength =
                storage.copiedBufferPeakByteLength > BigInt(byteLength)
                    ? storage.copiedBufferPeakByteLength
                    : BigInt(byteLength);
            return copy;
        };
        const copyFromWasmInto = (
            pointer: number,
            byteLength: number,
            destination: Uint8Array<ArrayBuffer>,
        ): Uint8Array<ArrayBuffer> => {
            if (byteLength > destination.byteLength) {
                throw new Error(
                    'The persistent browser evidence copy buffer is too small.',
                );
            }
            const exactDestination = destination.subarray(0, byteLength);
            exactDestination.set(
                new Uint8Array(context.memory.buffer, pointer, byteLength),
            );
            storage.copiedBufferPeakByteLength =
                storage.copiedBufferPeakByteLength > BigInt(byteLength)
                    ? storage.copiedBufferPeakByteLength
                    : BigInt(byteLength);
            return exactDestination;
        };
        const sampleWasmMemory = (): bigint =>
            BigInt(context.memory.buffer.byteLength);
        const manifestIdentityBytes = hexToBytes(
            nativeBinding.manifestIdentityShake256Hex,
        );
        const manifestIdentityPointer = context.allocate(
            manifestIdentityBytes.byteLength,
        );
        if (manifestIdentityPointer === 0) {
            throw new Error(
                'The release WebAssembly allocator refused manifest bytes.',
            );
        }
        new Uint8Array(
            context.memory.buffer,
            manifestIdentityPointer,
            manifestIdentityBytes.byteLength,
        ).set(manifestIdentityBytes);
        await delay(warmGuardBaselineMilliseconds);
        const wasmLinearMemoryStartByteLength = sampleWasmMemory();
        let wasmLinearMemoryPeakByteLength = wasmLinearMemoryStartByteLength;
        const operationStartedAtUnixMilliseconds = BigInt(Date.now());
        const operationStartedAtHighResolutionMilliseconds = performance.now();
        try {
            operationHandle = measureSynchronousArithmetic(timing, () =>
                checkedCall('browser evidence begin', () =>
                    wasmExports.sealed_lattice_proof_storage_width_browser_begin(
                        manifestIdentityPointer,
                        manifestIdentityBytes.byteLength,
                        statusPointer,
                    ),
                ),
            );
        } finally {
            manifestIdentityBytes.fill(0);
            context.deallocate(
                manifestIdentityPointer,
                nativeBinding.manifestIdentityShake256Hex.length / 2,
            );
        }
        if (operationHandle === 0) {
            throw new Error(
                'The release WebAssembly returned no evidence handle.',
            );
        }
        let progressPollsSinceYield = 0;
        let storageTransactionsSinceYield = 0;
        let expectedRequestSequence = 1n;
        let runtimeBindingHash: Uint8Array | undefined;
        let rustResult: RustEvidenceResult | undefined;
        while (rustResult === undefined) {
            const poll = measureSynchronousArithmetic(timing, () =>
                checkedCall('browser evidence poll', () =>
                    wasmExports.sealed_lattice_proof_storage_width_browser_poll(
                        operationHandle,
                        statusPointer,
                    ),
                ),
            );
            wasmLinearMemoryPeakByteLength =
                wasmLinearMemoryPeakByteLength > sampleWasmMemory()
                    ? wasmLinearMemoryPeakByteLength
                    : sampleWasmMemory();
            if (poll === pollComplete) {
                const observedResultByteLength = measureSynchronousArithmetic(
                    timing,
                    () =>
                        checkedCall('browser evidence result length', () =>
                            wasmExports.sealed_lattice_proof_storage_width_browser_result_byte_length(
                                operationHandle,
                                statusPointer,
                            ),
                        ),
                );
                if (observedResultByteLength !== resultByteLength) {
                    throw new Error(
                        'The browser evidence result layout changed.',
                    );
                }
                const copied = measureSynchronousArithmetic(timing, () =>
                    checkedCall('browser evidence result copy', () =>
                        wasmExports.sealed_lattice_proof_storage_width_browser_copy_result(
                            operationHandle,
                            resultPointer,
                            resultByteLength,
                            statusPointer,
                        ),
                    ),
                );
                if (copied !== resultByteLength) {
                    throw new Error(
                        'The browser evidence copied a partial result.',
                    );
                }
                rustResult = parseRustEvidenceResult(
                    copyFromWasm(resultPointer, resultByteLength),
                );
                continue;
            }
            if (poll === pollProgress) {
                progressPollsSinceYield += 1;
            } else if (poll === pollStorageRequest) {
                const requestByteLength = measureSynchronousArithmetic(
                    timing,
                    () =>
                        checkedCall('browser evidence request length', () =>
                            wasmExports.sealed_lattice_proof_storage_width_browser_pending_storage_request_byte_length(
                                operationHandle,
                                statusPointer,
                            ),
                        ),
                );
                if (
                    requestByteLength <= 0 ||
                    BigInt(requestByteLength) >
                        proofStorageWidthBrowserEvidenceProfile.maximumCopiedBufferByteLength
                ) {
                    throw new Error(
                        'The encoded storage request exceeds its copied-buffer cap.',
                    );
                }
                const copied = measureSynchronousArithmetic(timing, () =>
                    checkedCall('browser evidence request copy', () =>
                        wasmExports.sealed_lattice_proof_storage_width_browser_copy_pending_storage_request(
                            operationHandle,
                            storageBoundaryPointer,
                            requestByteLength,
                            statusPointer,
                        ),
                    ),
                );
                if (copied !== requestByteLength) {
                    throw new Error(
                        'The browser evidence copied a partial request.',
                    );
                }
                const encodedRequest = copyFromWasmInto(
                    storageBoundaryPointer,
                    requestByteLength,
                    encodedRequestBuffer,
                );
                const request = measureSynchronousArithmetic(timing, () =>
                    decodeCommonProofExternalMemoryRequest(
                        encodedRequest.byteLength ===
                            encodedRequestBuffer.byteLength
                            ? encodedRequest.slice()
                            : encodedRequest,
                    ),
                );
                if (request.requestSequence !== expectedRequestSequence) {
                    clearCommonProofExternalMemoryRequest(request);
                    throw new Error(
                        'The storage request sequence is not contiguous.',
                    );
                }
                expectedRequestSequence += 1n;
                if (runtimeBindingHash === undefined) {
                    runtimeBindingHash = request.runtimeBindingHash.slice();
                } else if (
                    !bytesEqual(runtimeBindingHash, request.runtimeBindingHash)
                ) {
                    clearCommonProofExternalMemoryRequest(request);
                    throw new Error(
                        'The storage runtime-binding hash changed mid-operation.',
                    );
                }
                let encodedResponse: Uint8Array;
                let responseEncoded = false;
                try {
                    const readResults = await measureStorageWait(timing, () =>
                        executeStorageRequest({
                            adapter,
                            databaseName: message.databaseName,
                            nativeBinding,
                            objects,
                            request,
                            storage,
                        }),
                    );
                    encodedResponse = measureSynchronousArithmetic(timing, () =>
                        encodeCommonProofExternalMemoryResponseInto(
                            request,
                            readResults,
                            encodedResponseBuffer,
                        ),
                    );
                    responseEncoded = true;
                } finally {
                    if (!responseEncoded) {
                        clearCommonProofExternalMemoryRequest(request);
                    }
                }
                storage.copiedBufferPeakByteLength =
                    storage.copiedBufferPeakByteLength >
                    BigInt(encodedResponse.byteLength)
                        ? storage.copiedBufferPeakByteLength
                        : BigInt(encodedResponse.byteLength);
                if (
                    BigInt(encodedResponse.byteLength) >
                    proofStorageWidthBrowserEvidenceProfile.maximumCopiedBufferByteLength
                ) {
                    encodedResponse.fill(0);
                    throw new Error(
                        'The encoded storage response exceeds its copied-buffer cap.',
                    );
                }
                try {
                    new Uint8Array(
                        context.memory.buffer,
                        storageBoundaryPointer,
                        encodedResponse.byteLength,
                    ).set(encodedResponse);
                    const supplied = measureSynchronousArithmetic(timing, () =>
                        checkedCall('browser evidence response supply', () =>
                            wasmExports.sealed_lattice_proof_storage_width_browser_supply_storage_response(
                                operationHandle,
                                storageBoundaryPointer,
                                encodedResponse.byteLength,
                                statusPointer,
                            ),
                        ),
                    );
                    if (supplied !== encodedResponse.byteLength) {
                        throw new Error(
                            'The browser evidence supplied a partial response.',
                        );
                    }
                } finally {
                    encodedResponse.fill(0);
                }
                storageTransactionsSinceYield += 1;
            } else {
                throw new Error(
                    `The browser evidence returned unknown poll ${String(poll)}.`,
                );
            }
            if (
                progressPollsSinceYield >=
                    proofStorageWidthBrowserEvidenceProfile.arithmeticProgressPollsPerYield ||
                storageTransactionsSinceYield >=
                    proofStorageWidthBrowserEvidenceProfile.storageTransactionsPerYield
            ) {
                await yieldBrowserTurn(timing);
                progressPollsSinceYield = 0;
                storageTransactionsSinceYield = 0;
            }
        }
        wasmExports.sealed_lattice_proof_storage_width_browser_release(
            operationHandle,
        );
        operationReleased = true;
        operationHandle = 0;
        runtimeBindingHash?.fill(0);
        const operationFinishedAtUnixMilliseconds = BigInt(Date.now());
        const measuredOperationNanoseconds = millisecondsToNanoseconds(
            performance.now() - operationStartedAtHighResolutionMilliseconds,
        );
        const classifiedWithoutCoordinator =
            timing.arithmeticNanoseconds +
            timing.externalStorageWaitNanoseconds +
            timing.workerYieldNanoseconds;
        const coordinatorNanoseconds =
            measuredOperationNanoseconds > classifiedWithoutCoordinator
                ? measuredOperationNanoseconds - classifiedWithoutCoordinator
                : 0n;
        const operationElapsedNanoseconds =
            classifiedWithoutCoordinator + coordinatorNanoseconds;
        const wasmLinearMemoryEndByteLength = sampleWasmMemory();
        wasmLinearMemoryPeakByteLength =
            wasmLinearMemoryPeakByteLength > wasmLinearMemoryEndByteLength
                ? wasmLinearMemoryPeakByteLength
                : wasmLinearMemoryEndByteLength;
        const externalCommittedTransactionCount =
            storage.externalCommittedCreateTransactionCount +
            storage.externalCommittedReadTransactionCount +
            storage.externalCommittedSealTransactionCount +
            storage.externalCommittedWriteTransactionCount +
            storage.externalCommittedDeleteTransactionCount;
        if (
            objects.size !== 0 ||
            storage.currentStoredByteLength !== 0n ||
            storage.replaySourceWrittenByteLength !==
                rustResult.sourceReplayByteLength ||
            storage.proofArtifactWrittenByteLength !==
                rustResult.canonicalArtifactByteLength ||
            storage.externalReadByteLength !==
                rustResult.externalReadByteLength ||
            storage.externalWrittenByteLength !==
                rustResult.externalWrittenByteLength ||
            externalCommittedTransactionCount !==
                rustResult.externalCommittedTransactionCount ||
            storage.sourceCommittedTransactionCount !==
                rustResult.sourceCommittedTransactionCount ||
            storage.sourceObjectSealTransactionCount !==
                rustResult.sourceObjectSealTransactionCount ||
            storage.proofObjectSealTransactionCount !==
                rustResult.proofObjectSealTransactionCount ||
            storage.physicalObjectPeak !== rustResult.physicalObjectPeak ||
            storage.storedScratchPeakByteLength !==
                rustResult.storedScratchPeakByteLength
        ) {
            throw new Error('Rust and IndexedDB custody accounting diverged.');
        }
        const remainingKeys = await adapter.listKeys('');
        storage.providerCleanupInspectionTransactionCount += 1n;
        if (remainingKeys.length !== 0) {
            throw new Error(
                'IndexedDB retained browser evidence records after completion.',
            );
        }
        const providerTransactionCount =
            storage.providerMutationTransactionCount +
            storage.providerReadTransactionCount +
            storage.providerCleanupInspectionTransactionCount;
        const rawMeasurement = {
            absorbedLeafValueCountDecimal:
                rustResult.absorbedLeafValueCount.toString(),
            activeColumnLdeScratchByteLengthDecimal:
                nativeBinding.activeColumnLdeScratchByteLength.toString(),
            arithmeticNanosecondsDecimal:
                timing.arithmeticNanoseconds.toString(),
            artifactShake256Hex: rustResult.artifactShake256Hex,
            backendProfileIdentifier:
                proofStorageWidthProfile.backendProfileIdentifier,
            baseLeafObjectReadByteLengthDecimal: '0',
            baseLeafObjectWrittenByteLengthDecimal: '0',
            baseRootShake256Hex: rustResult.baseRootShake256Hex,
            canonicalArtifactByteLengthDecimal:
                rustResult.canonicalArtifactByteLength.toString(),
            canonicalArtifactNonleafRangeChunkCountDecimal:
                rustResult.canonicalArtifactNonleafRangeChunkCount.toString(),
            canonicalArtifactPostleafRangeChunkCountDecimal:
                rustResult.canonicalArtifactPostleafRangeChunkCount.toString(),
            canonicalArtifactPreleafRangeChunkCountDecimal:
                rustResult.canonicalArtifactPreleafRangeChunkCount.toString(),
            coordinatorNanosecondsDecimal: coordinatorNanoseconds.toString(),
            copiedBufferPeakByteLengthDecimal:
                storage.copiedBufferPeakByteLength.toString(),
            custodyCleanupCompleted: rustResult.custodyCleanupCompleted,
            custodyModel: 'bounded-external-storage-replay',
            custodySchemaIdentifier:
                proofStorageWidthProfile.custodySchemaIdentifier,
            exactCandidate: {
                firstDataModulus: proofStorageWidthProfile.firstDataModulus,
                materialRadix: proofStorageWidthProfile.materialRadix,
                plaintextModulus: 257,
                ringDimension: 32_768,
                rosterSize: 10,
            },
            externalCommittedCreateTransactionCountDecimal:
                storage.externalCommittedCreateTransactionCount.toString(),
            externalCommittedDeleteTransactionCountDecimal:
                storage.externalCommittedDeleteTransactionCount.toString(),
            externalCommittedReadTransactionCountDecimal:
                storage.externalCommittedReadTransactionCount.toString(),
            externalCommittedSealTransactionCountDecimal:
                storage.externalCommittedSealTransactionCount.toString(),
            externalCommittedTransactionCountDecimal:
                externalCommittedTransactionCount.toString(),
            externalCommittedWriteTransactionCountDecimal:
                storage.externalCommittedWriteTransactionCount.toString(),
            externalReadByteLengthDecimal:
                storage.externalReadByteLength.toString(),
            externalStorageWaitNanosecondsDecimal:
                timing.externalStorageWaitNanoseconds.toString(),
            externalWrittenByteLengthDecimal:
                storage.externalWrittenByteLength.toString(),
            formatVersion: 1,
            frozenInputIdentityHashDomain:
                proofStorageWidthProfile.frozenInputIdentityHashDomain,
            frozenInputIdentityShake256Hex:
                proofStorageWidthProfile.frozenInputIdentityShake256Hex,
            frozenInputRecipeIdentifier:
                proofStorageWidthProfile.frozenInputRecipeIdentifier,
            inputIdentityShake256Hex: rustResult.inputIdentityShake256Hex,
            intendedReleaseRuntime:
                proofStorageWidthProfile.intendedReleaseRuntime,
            ldeTransformCountDecimal: rustResult.ldeTransformCount.toString(),
            localRecordSealInvocationCountDecimal:
                rustResult.localRecordSealInvocationCount.toString(),
            manifestIdentityShake256Hex: rustResult.manifestIdentityShake256Hex,
            maximumArithmeticSliceNanosecondsDecimal:
                timing.maximumArithmeticSliceNanoseconds.toString(),
            maximumTransactionPayloadByteLengthDecimal:
                nativeBinding.maximumTransactionPayloadByteLength.toString(),
            measurementRuntime: 'desktop-browser-wasm',
            openedLeafElementByteLengthDecimal:
                rustResult.openedLeafElementByteLength.toString(),
            openedLeafRangeChunkCountDecimal:
                rustResult.openedLeafRangeChunkCount.toString(),
            openedValueCountDecimal: rustResult.openedValueCount.toString(),
            operationElapsedNanosecondsDecimal:
                operationElapsedNanoseconds.toString(),
            operationFinishedAtUnixMilliseconds:
                operationFinishedAtUnixMilliseconds.toString(),
            operationStartedAtUnixMilliseconds:
                operationStartedAtUnixMilliseconds.toString(),
            persistedBaseLeafByteLengthDecimal: '0',
            persistedLdeByteLengthDecimal: '0',
            physicalObjectPeakDecimal: storage.physicalObjectPeak.toString(),
            proofByteLengthDecimal:
                rustResult.canonicalArtifactByteLength.toString(),
            proofObjectSealTransactionCountDecimal:
                storage.proofObjectSealTransactionCount.toString(),
            proofPhysicalObjectCountDecimal: '1',
            providerCleanupInspectionTransactionCountDecimal:
                storage.providerCleanupInspectionTransactionCount.toString(),
            providerDataRecordPeakDecimal:
                storage.providerDataRecordPeak.toString(),
            providerMetadataRecordPeakDecimal:
                storage.providerMetadataRecordPeak.toString(),
            providerMetadataWrittenByteLengthDecimal:
                storage.providerMetadataWrittenByteLength.toString(),
            providerMutationTransactionCountDecimal:
                storage.providerMutationTransactionCount.toString(),
            providerReadTransactionCountDecimal:
                storage.providerReadTransactionCount.toString(),
            providerRecordPeakDecimal: storage.providerRecordPeak.toString(),
            providerTransactionCountDecimal:
                providerTransactionCount.toString(),
            publicBaseLeafByteLengthDecimal:
                rustResult.publicBaseLeafByteLength.toString(),
            publicBaseLeafColumnCount: representativeWidth,
            publicColumnDerivationAlgorithm:
                proofStorageWidthProfile.publicColumnDerivationAlgorithm,
            publicColumnInputDomain:
                proofStorageWidthProfile.publicColumnInputDomain,
            publicColumnSeedHex: proofStorageWidthProfile.publicColumnSeedHex,
            queriedLeafPayloadByteLengthDecimal:
                rustResult.queriedLeafPayloadByteLength.toString(),
            recomputedCanonicalArtifactByteLengthDecimal:
                rustResult.recomputedCanonicalArtifactByteLength.toString(),
            releaseProfileIdentifier:
                proofStorageWidthProfile.releaseProfileIdentifier,
            sealedSecretPlaintextByteLengthDecimal:
                rustResult.sealedSecretPlaintextByteLength.toString(),
            sourceCommittedTransactionCountDecimal:
                storage.sourceCommittedTransactionCount.toString(),
            sourceObjectSealTransactionCountDecimal:
                storage.sourceObjectSealTransactionCount.toString(),
            sourcePhysicalObjectCountDecimal: String(representativeWidth),
            sourceReplayByteLengthDecimal:
                rustResult.sourceReplayByteLength.toString(),
            storedScratchPeakByteLengthDecimal:
                storage.storedScratchPeakByteLength.toString(),
            wasmLinearMemoryEndByteLengthDecimal:
                wasmLinearMemoryEndByteLength.toString(),
            wasmLinearMemoryPeakByteLengthDecimal:
                wasmLinearMemoryPeakByteLength.toString(),
            wasmLinearMemoryStartByteLengthDecimal:
                wasmLinearMemoryStartByteLength.toString(),
            wasmSha256Hex: message.wasmSha256Hex,
            workerYieldCountDecimal: timing.workerYieldCount.toString(),
            workerYieldNanosecondsDecimal:
                timing.workerYieldNanoseconds.toString(),
            widthDependentQueriedBaseOpeningByteLengthDecimal:
                nativeBinding.widthDependentQueriedBaseOpeningByteLength.toString(),
            widthInputIdentityHashDomain:
                proofStorageWidthProfile.widthInputIdentityHashDomain,
        };
        const measurement =
            parseProofStorageWidthBrowserMeasurement(rawMeasurement);
        requireProofStorageWidthBrowserNativeMatch(measurement, nativeBinding);
        completedMeasurement = measurement;
    } catch (error) {
        primaryFailure = error;
    }
    const cleanupFailures: unknown[] = [];
    if (operationHandle !== 0 && !operationReleased) {
        try {
            wasmExports.sealed_lattice_proof_storage_width_browser_cancel(
                operationHandle,
            );
        } catch (error) {
            cleanupFailures.push(error);
        }
        try {
            wasmExports.sealed_lattice_proof_storage_width_browser_release(
                operationHandle,
            );
            operationReleased = true;
            operationHandle = 0;
        } catch (error) {
            cleanupFailures.push(error);
        }
    }
    encodedRequestBuffer.fill(0);
    encodedResponseBuffer.fill(0);
    for (const [pointer, byteLength] of [
        [storageBoundaryPointer, storageBoundaryBufferByteLength],
        [resultPointer, resultByteLength],
        [statusPointer, statusByteLength],
    ] as const) {
        if (pointer !== 0) {
            try {
                context.deallocate(pointer, byteLength);
            } catch (error) {
                cleanupFailures.push(error);
            }
        }
    }
    try {
        await adapter.close();
    } catch (error) {
        cleanupFailures.push(error);
    }
    try {
        await deleteDatabase(indexedDbFactory, message.databaseName);
    } catch (error) {
        cleanupFailures.push(error);
    }
    if (cleanupFailures.length > 0) {
        throw Object.assign(new Error('The browser evidence cleanup failed.'), {
            causes: Object.freeze(
                primaryFailure === undefined
                    ? cleanupFailures
                    : [primaryFailure, ...cleanupFailures],
            ),
        });
    }
    if (primaryFailure !== undefined) {
        throw primaryFailure instanceof Error
            ? primaryFailure
            : Object.assign(
                  new Error(
                      'The browser evidence failed with a non-Error value.',
                  ),
                  { cause: primaryFailure },
              );
    }
    if (completedMeasurement === undefined) {
        throw new Error(
            'The browser evidence ended without a result or failure.',
        );
    }
    return completedMeasurement;
};

let started = false;
workerScope.addEventListener('message', (event) => {
    if (started) {
        workerScope.postMessage({
            failureMessage:
                'The proof-storage width browser worker accepts exactly one operation.',
            messageKind: 'failure',
        });
        return;
    }
    started = true;
    let message: StartMessage;
    try {
        message = parseStartMessage(event.data);
    } catch (error) {
        workerScope.postMessage({
            failureMessage:
                error instanceof Error
                    ? error.message
                    : 'The browser evidence start message was rejected.',
            messageKind: 'failure',
        });
        return;
    }
    void runBrowserEvidence(message)
        .then((measurement) => {
            workerScope.postMessage({
                measurement:
                    serializeProofStorageWidthBrowserMeasurement(measurement),
                messageKind: 'measurement',
            });
        })
        .catch((error: unknown) => {
            workerScope.postMessage({
                failureMessage:
                    error instanceof Error
                        ? error.message
                        : 'The browser evidence operation failed.',
                messageKind: 'failure',
            });
        });
});
