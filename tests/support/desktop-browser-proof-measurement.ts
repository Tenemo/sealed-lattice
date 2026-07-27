const sha512HexPattern = /^[0-9a-f]{128}$/u;
const sha256HexPattern = /^[0-9a-f]{64}$/u;
const wasmPageByteLength = 65_536;

export const desktopBrowserProofMeasurementConsolePrefix =
    'sealed-lattice-desktop-browser-proof-measurement:';
export const emptyCanonicalByteSequenceSha512Hex =
    'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e';

export type DesktopBrowserProofExecutionKind =
    | 'cancelled-generation'
    | 'deterministic-parity'
    | 'fresh-generation'
    | 'refused-generation'
    | 'replay'
    | 'resumed-generation'
    | 'verification'
    | 'worker-reuse-generation';

export type DesktopBrowserProofCacheState = 'cold' | 'warm';

export type DesktopBrowserProofCancellationBoundaryKind =
    | 'safe-boundary'
    | 'storage-yield';

export type DesktopBrowserProofResourceAccounting = Readonly<{
    cleanupCompleted: boolean;
    cleanupDeletedByteLength: number;
    cleanupDeletionCount: number;
    cleanupDurationMilliseconds: number;
    commitReadbackByteLength: number;
    commitReadbackCallCount: number;
    ciphertextReadByteLength: number;
    ciphertextReadCallCount: number;
    ciphertextWriteByteLength: number;
    ciphertextWriteCallCount: number;
    deletionDurationMilliseconds: number;
    deterministicRegeneratedByteLength: number;
    deterministicRegenerationCallCount: number;
    indexedDbRequestCount: number;
    indexedDbTransactionCount: number;
    javascriptToWasmCopyByteLength: number;
    javascriptToWasmCopyCount: number;
    kernelStorageRequestCount: number;
    openCallCount: number;
    openCiphertextByteLength: number;
    openPlaintextByteLength: number;
    physicalQuotaByteLength: number;
    physicalQuotaHeadroomByteLength: number;
    physicalQuotaReservedByteLength: number;
    physicalStoredEndByteLength: number;
    physicalStoredPeakByteLength: number;
    plaintextReadByteLength: number;
    plaintextReadCallCount: number;
    plaintextWriteByteLength: number;
    plaintextWriteCallCount: number;
    repairHashCallCount: number;
    repairHashedByteLength: number;
    sealCallCount: number;
    sealCiphertextByteLength: number;
    sealPlaintextByteLength: number;
    simultaneousLiveBufferPeakByteLength: number;
    simultaneousLiveBufferPeakCount: number;
    wasmToJavascriptCopyByteLength: number;
    wasmToJavascriptCopyCount: number;
    workerTransferByteLength: number;
    workerTransferCount: number;
}>;

export type DesktopBrowserProofMeasurementRecord = Readonly<{
    browserCacheState: DesktopBrowserProofCacheState;
    browserProcessResidentMemoryEndByteLength: number;
    browserProcessResidentMemoryPeakByteLength: number;
    browserProcessResidentMemoryStartByteLength: number;
    canonicalInputByteLength: number;
    canonicalInputSha512Hex: string;
    canonicalOutputByteLength: number;
    caseIdentifier: string;
    copiedBufferPeakByteLength: number;
    cancellationBoundaryCatalogSha512Hex?: string;
    cancellationBoundaryIdentifier?: string;
    cancellationBoundaryKind?: DesktopBrowserProofCancellationBoundaryKind;
    cancellationBoundaryOrdinal?: number;
    declaredSafeBoundaryCount?: number;
    declaredStorageYieldBoundaryCount?: number;
    deterministicCoinBindingSha512Hex?: string;
    durationMilliseconds: number;
    executionKind: DesktopBrowserProofExecutionKind;
    externalScratchPeakByteLength: number;
    externalScratchReadByteLength: number;
    externalScratchTransactionCount: number;
    externalScratchWriteByteLength: number;
    finishedAtUnixMilliseconds: number;
    fullBufferCopiedByteLength: number;
    fullBufferCopyCount: number;
    observedHostAllocationVolumeByteLength: number;
    javascriptHeapEndByteLength: number;
    javascriptHeapPeakByteLength: number;
    javascriptHeapStartByteLength: number;
    nativeReferenceByteLength?: number;
    nativeReferenceSha512Hex?: string;
    outputSha512Hex: string;
    refusalReasonIdentifier?: string;
    resourceAccounting: DesktopBrowserProofResourceAccounting;
    retainedResidentPeakByteLength: number;
    runOrdinal: number;
    suiteId: string;
    startedAtUnixMilliseconds: number;
    wasmSha256Hex: string;
    wasmLinearMemoryEndByteLength: number;
    wasmLinearMemoryEndPageCount: number;
    wasmLinearMemoryPeakByteLength: number;
    wasmLinearMemoryPeakPageCount: number;
    wasmLinearMemoryStartByteLength: number;
    wasmLinearMemoryStartPageCount: number;
    workerInstanceIdentifier: string;
    workerOperationOrdinal: number;
}>;

type MemoryReaders = Readonly<{
    browserProcessResidentMemoryByteLength: () => number;
    externalScratchByteLength: () => number;
    javascriptHeapByteLength: () => number;
    retainedResidentByteLength: () => number;
    wasmLinearMemoryByteLength: () => number;
}>;

type MemoryObservation = Readonly<{
    browserProcessResidentMemoryByteLength: number;
    externalScratchByteLength: number;
    javascriptHeapByteLength: number;
    retainedResidentByteLength: number;
    wasmLinearMemoryByteLength: number;
}>;

type DesktopBrowserProofMeasurement = Readonly<{
    finish(input: {
        canonicalInputByteLength: number;
        canonicalInputSha512Hex: string;
        canonicalOutputByteLength: number;
        copiedBufferPeakByteLength: number;
        externalScratchPeakByteLength: number;
        externalScratchReadByteLength: number;
        externalScratchTransactionCount: number;
        externalScratchWriteByteLength: number;
        fullBufferCopiedByteLength: number;
        fullBufferCopyCount: number;
        observedHostAllocationVolumeByteLength: number;
        outputSha512Hex: string;
        resourceAccounting: DesktopBrowserProofResourceAccounting;
        cancellationBoundaryCatalogSha512Hex?: string;
        cancellationBoundaryIdentifier?: string;
        cancellationBoundaryKind?: DesktopBrowserProofCancellationBoundaryKind;
        cancellationBoundaryOrdinal?: number;
        declaredSafeBoundaryCount?: number;
        declaredStorageYieldBoundaryCount?: number;
        deterministicCoinBindingSha512Hex?: string;
        nativeReferenceByteLength?: number;
        nativeReferenceSha512Hex?: string;
        refusalReasonIdentifier?: string;
    }): DesktopBrowserProofMeasurementRecord;
    sample(): void;
    yieldControl(): Promise<void>;
}>;

const requireNonnegativeSafeInteger = (
    value: unknown,
    fieldName: string,
): number => {
    if (!Number.isSafeInteger(value) || Number(value) < 0) {
        throw new TypeError(`${fieldName} must be a nonnegative safe integer.`);
    }
    return Number(value);
};

const requirePositiveSafeInteger = (
    value: unknown,
    fieldName: string,
): number => {
    const number = requireNonnegativeSafeInteger(value, fieldName);
    if (number === 0) {
        throw new TypeError(`${fieldName} must be positive.`);
    }
    return number;
};

const requireFiniteNonnegativeNumber = (
    value: unknown,
    fieldName: string,
): number => {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a nonnegative finite number.`,
        );
    }
    return value;
};

const requireNonemptyIdentifier = (
    value: unknown,
    fieldName: string,
): string => {
    if (
        typeof value !== 'string' ||
        !/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(value)
    ) {
        throw new TypeError(`${fieldName} must be a kebab-case identifier.`);
    }
    return value;
};

const requireSha512Hex = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || !sha512HexPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a lowercase SHA-512 digest.`);
    }
    return value;
};

const requireRecord = (
    value: unknown,
    fieldName: string,
): Readonly<Record<string, unknown>> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }
    return value as Readonly<Record<string, unknown>>;
};

const resourceAccountingFieldNames = Object.freeze([
    'cleanupCompleted',
    'cleanupDeletedByteLength',
    'cleanupDeletionCount',
    'cleanupDurationMilliseconds',
    'commitReadbackByteLength',
    'commitReadbackCallCount',
    'ciphertextReadByteLength',
    'ciphertextReadCallCount',
    'ciphertextWriteByteLength',
    'ciphertextWriteCallCount',
    'deletionDurationMilliseconds',
    'deterministicRegeneratedByteLength',
    'deterministicRegenerationCallCount',
    'indexedDbRequestCount',
    'indexedDbTransactionCount',
    'javascriptToWasmCopyByteLength',
    'javascriptToWasmCopyCount',
    'kernelStorageRequestCount',
    'openCallCount',
    'openCiphertextByteLength',
    'openPlaintextByteLength',
    'physicalQuotaByteLength',
    'physicalQuotaHeadroomByteLength',
    'physicalQuotaReservedByteLength',
    'physicalStoredEndByteLength',
    'physicalStoredPeakByteLength',
    'plaintextReadByteLength',
    'plaintextReadCallCount',
    'plaintextWriteByteLength',
    'plaintextWriteCallCount',
    'repairHashCallCount',
    'repairHashedByteLength',
    'sealCallCount',
    'sealCiphertextByteLength',
    'sealPlaintextByteLength',
    'simultaneousLiveBufferPeakByteLength',
    'simultaneousLiveBufferPeakCount',
    'wasmToJavascriptCopyByteLength',
    'wasmToJavascriptCopyCount',
    'workerTransferByteLength',
    'workerTransferCount',
] as const satisfies readonly (keyof DesktopBrowserProofResourceAccounting)[]);

const requireExactKeys = (
    record: Readonly<Record<string, unknown>>,
    expectedKeys: readonly string[],
    fieldName: string,
): void => {
    const actualKeys = Object.keys(record).sort();
    const sortedExpectedKeys = [...expectedKeys].sort();
    if (
        actualKeys.length !== sortedExpectedKeys.length ||
        actualKeys.some(
            (actualKey, keyIndex) => actualKey !== sortedExpectedKeys[keyIndex],
        )
    ) {
        throw new TypeError(`${fieldName} does not contain its exact fields.`);
    }
};

const requireCallAndByteAccounting = (
    callCount: number,
    byteLength: number,
    fieldName: string,
): void => {
    if ((callCount === 0) !== (byteLength === 0)) {
        throw new TypeError(
            `${fieldName} call count and byte length are inconsistent.`,
        );
    }
};

export const parseDesktopBrowserProofResourceAccounting = (
    value: unknown,
): DesktopBrowserProofResourceAccounting => {
    const record = requireRecord(value, 'resourceAccounting');
    requireExactKeys(
        record,
        resourceAccountingFieldNames,
        'resourceAccounting',
    );
    if (record.cleanupCompleted !== true) {
        throw new TypeError('cleanupCompleted must be true.');
    }
    const accounting: DesktopBrowserProofResourceAccounting = {
        cleanupCompleted: true,
        cleanupDeletedByteLength: requireNonnegativeSafeInteger(
            record.cleanupDeletedByteLength,
            'cleanupDeletedByteLength',
        ),
        cleanupDeletionCount: requireNonnegativeSafeInteger(
            record.cleanupDeletionCount,
            'cleanupDeletionCount',
        ),
        cleanupDurationMilliseconds: requireFiniteNonnegativeNumber(
            record.cleanupDurationMilliseconds,
            'cleanupDurationMilliseconds',
        ),
        commitReadbackByteLength: requireNonnegativeSafeInteger(
            record.commitReadbackByteLength,
            'commitReadbackByteLength',
        ),
        commitReadbackCallCount: requireNonnegativeSafeInteger(
            record.commitReadbackCallCount,
            'commitReadbackCallCount',
        ),
        ciphertextReadByteLength: requireNonnegativeSafeInteger(
            record.ciphertextReadByteLength,
            'ciphertextReadByteLength',
        ),
        ciphertextReadCallCount: requireNonnegativeSafeInteger(
            record.ciphertextReadCallCount,
            'ciphertextReadCallCount',
        ),
        ciphertextWriteByteLength: requireNonnegativeSafeInteger(
            record.ciphertextWriteByteLength,
            'ciphertextWriteByteLength',
        ),
        ciphertextWriteCallCount: requireNonnegativeSafeInteger(
            record.ciphertextWriteCallCount,
            'ciphertextWriteCallCount',
        ),
        deletionDurationMilliseconds: requireFiniteNonnegativeNumber(
            record.deletionDurationMilliseconds,
            'deletionDurationMilliseconds',
        ),
        deterministicRegeneratedByteLength: requireNonnegativeSafeInteger(
            record.deterministicRegeneratedByteLength,
            'deterministicRegeneratedByteLength',
        ),
        deterministicRegenerationCallCount: requireNonnegativeSafeInteger(
            record.deterministicRegenerationCallCount,
            'deterministicRegenerationCallCount',
        ),
        indexedDbRequestCount: requireNonnegativeSafeInteger(
            record.indexedDbRequestCount,
            'indexedDbRequestCount',
        ),
        indexedDbTransactionCount: requireNonnegativeSafeInteger(
            record.indexedDbTransactionCount,
            'indexedDbTransactionCount',
        ),
        javascriptToWasmCopyByteLength: requireNonnegativeSafeInteger(
            record.javascriptToWasmCopyByteLength,
            'javascriptToWasmCopyByteLength',
        ),
        javascriptToWasmCopyCount: requireNonnegativeSafeInteger(
            record.javascriptToWasmCopyCount,
            'javascriptToWasmCopyCount',
        ),
        kernelStorageRequestCount: requireNonnegativeSafeInteger(
            record.kernelStorageRequestCount,
            'kernelStorageRequestCount',
        ),
        openCallCount: requireNonnegativeSafeInteger(
            record.openCallCount,
            'openCallCount',
        ),
        openCiphertextByteLength: requireNonnegativeSafeInteger(
            record.openCiphertextByteLength,
            'openCiphertextByteLength',
        ),
        openPlaintextByteLength: requireNonnegativeSafeInteger(
            record.openPlaintextByteLength,
            'openPlaintextByteLength',
        ),
        physicalQuotaByteLength: requirePositiveSafeInteger(
            record.physicalQuotaByteLength,
            'physicalQuotaByteLength',
        ),
        physicalQuotaHeadroomByteLength: requireNonnegativeSafeInteger(
            record.physicalQuotaHeadroomByteLength,
            'physicalQuotaHeadroomByteLength',
        ),
        physicalQuotaReservedByteLength: requireNonnegativeSafeInteger(
            record.physicalQuotaReservedByteLength,
            'physicalQuotaReservedByteLength',
        ),
        physicalStoredEndByteLength: requireNonnegativeSafeInteger(
            record.physicalStoredEndByteLength,
            'physicalStoredEndByteLength',
        ),
        physicalStoredPeakByteLength: requireNonnegativeSafeInteger(
            record.physicalStoredPeakByteLength,
            'physicalStoredPeakByteLength',
        ),
        plaintextReadByteLength: requireNonnegativeSafeInteger(
            record.plaintextReadByteLength,
            'plaintextReadByteLength',
        ),
        plaintextReadCallCount: requireNonnegativeSafeInteger(
            record.plaintextReadCallCount,
            'plaintextReadCallCount',
        ),
        plaintextWriteByteLength: requireNonnegativeSafeInteger(
            record.plaintextWriteByteLength,
            'plaintextWriteByteLength',
        ),
        plaintextWriteCallCount: requireNonnegativeSafeInteger(
            record.plaintextWriteCallCount,
            'plaintextWriteCallCount',
        ),
        repairHashCallCount: requireNonnegativeSafeInteger(
            record.repairHashCallCount,
            'repairHashCallCount',
        ),
        repairHashedByteLength: requireNonnegativeSafeInteger(
            record.repairHashedByteLength,
            'repairHashedByteLength',
        ),
        sealCallCount: requireNonnegativeSafeInteger(
            record.sealCallCount,
            'sealCallCount',
        ),
        sealCiphertextByteLength: requireNonnegativeSafeInteger(
            record.sealCiphertextByteLength,
            'sealCiphertextByteLength',
        ),
        sealPlaintextByteLength: requireNonnegativeSafeInteger(
            record.sealPlaintextByteLength,
            'sealPlaintextByteLength',
        ),
        simultaneousLiveBufferPeakByteLength: requireNonnegativeSafeInteger(
            record.simultaneousLiveBufferPeakByteLength,
            'simultaneousLiveBufferPeakByteLength',
        ),
        simultaneousLiveBufferPeakCount: requireNonnegativeSafeInteger(
            record.simultaneousLiveBufferPeakCount,
            'simultaneousLiveBufferPeakCount',
        ),
        wasmToJavascriptCopyByteLength: requireNonnegativeSafeInteger(
            record.wasmToJavascriptCopyByteLength,
            'wasmToJavascriptCopyByteLength',
        ),
        wasmToJavascriptCopyCount: requireNonnegativeSafeInteger(
            record.wasmToJavascriptCopyCount,
            'wasmToJavascriptCopyCount',
        ),
        workerTransferByteLength: requireNonnegativeSafeInteger(
            record.workerTransferByteLength,
            'workerTransferByteLength',
        ),
        workerTransferCount: requireNonnegativeSafeInteger(
            record.workerTransferCount,
            'workerTransferCount',
        ),
    };

    for (const [callCount, byteLength, fieldName] of [
        [
            accounting.cleanupDeletionCount,
            accounting.cleanupDeletedByteLength,
            'cleanup deletion',
        ],
        [
            accounting.commitReadbackCallCount,
            accounting.commitReadbackByteLength,
            'commit readback',
        ],
        [
            accounting.ciphertextReadCallCount,
            accounting.ciphertextReadByteLength,
            'ciphertext read',
        ],
        [
            accounting.ciphertextWriteCallCount,
            accounting.ciphertextWriteByteLength,
            'ciphertext write',
        ],
        [
            accounting.deterministicRegenerationCallCount,
            accounting.deterministicRegeneratedByteLength,
            'deterministic regeneration',
        ],
        [
            accounting.javascriptToWasmCopyCount,
            accounting.javascriptToWasmCopyByteLength,
            'JavaScript-to-WebAssembly copy',
        ],
        [
            accounting.plaintextReadCallCount,
            accounting.plaintextReadByteLength,
            'plaintext read',
        ],
        [
            accounting.plaintextWriteCallCount,
            accounting.plaintextWriteByteLength,
            'plaintext write',
        ],
        [
            accounting.repairHashCallCount,
            accounting.repairHashedByteLength,
            'repair hash',
        ],
        [
            accounting.simultaneousLiveBufferPeakCount,
            accounting.simultaneousLiveBufferPeakByteLength,
            'simultaneous live buffer peak',
        ],
        [
            accounting.wasmToJavascriptCopyCount,
            accounting.wasmToJavascriptCopyByteLength,
            'WebAssembly-to-JavaScript copy',
        ],
        [
            accounting.workerTransferCount,
            accounting.workerTransferByteLength,
            'worker transfer',
        ],
    ] as const) {
        requireCallAndByteAccounting(callCount, byteLength, fieldName);
    }
    if (
        (accounting.sealCallCount === 0) !==
            (accounting.sealPlaintextByteLength === 0) ||
        (accounting.sealCallCount === 0) !==
            (accounting.sealCiphertextByteLength === 0)
    ) {
        throw new TypeError('Seal call and byte accounting is inconsistent.');
    }
    if (
        (accounting.openCallCount === 0) !==
            (accounting.openCiphertextByteLength === 0) ||
        (accounting.openCallCount === 0) !==
            (accounting.openPlaintextByteLength === 0)
    ) {
        throw new TypeError('Open call and byte accounting is inconsistent.');
    }
    if (
        accounting.indexedDbRequestCount < accounting.indexedDbTransactionCount
    ) {
        throw new TypeError(
            'IndexedDB request count is below its transaction count.',
        );
    }
    if (
        accounting.javascriptToWasmCopyCount >
            accounting.kernelStorageRequestCount +
                accounting.plaintextReadCallCount +
                accounting.commitReadbackCallCount ||
        accounting.wasmToJavascriptCopyCount >
            accounting.kernelStorageRequestCount +
                accounting.plaintextWriteCallCount
    ) {
        throw new TypeError(
            'JavaScript and WebAssembly copy accounting exceeds the observed storage requests and logical payload boundaries.',
        );
    }
    if (
        accounting.physicalStoredEndByteLength >
            accounting.physicalStoredPeakByteLength ||
        accounting.physicalQuotaHeadroomByteLength >
            accounting.physicalQuotaByteLength ||
        accounting.physicalQuotaReservedByteLength >
            accounting.physicalQuotaByteLength -
                accounting.physicalQuotaHeadroomByteLength ||
        accounting.physicalStoredPeakByteLength >
            accounting.physicalQuotaReservedByteLength ||
        accounting.physicalStoredPeakByteLength >
            accounting.physicalQuotaByteLength -
                accounting.physicalQuotaHeadroomByteLength
    ) {
        throw new TypeError(
            'Physical storage, reservation, quota, and headroom accounting is inconsistent.',
        );
    }
    return Object.freeze(accounting);
};

const cacheStates = new Set<DesktopBrowserProofCacheState>(['cold', 'warm']);

const requireCacheState = (value: unknown): DesktopBrowserProofCacheState => {
    if (
        typeof value !== 'string' ||
        !cacheStates.has(value as DesktopBrowserProofCacheState)
    ) {
        throw new TypeError('browserCacheState must be cold or warm.');
    }
    return value as DesktopBrowserProofCacheState;
};

const cancellationBoundaryKinds =
    new Set<DesktopBrowserProofCancellationBoundaryKind>([
        'safe-boundary',
        'storage-yield',
    ]);

const optionalCancellationBoundaryKind = (
    value: unknown,
): DesktopBrowserProofCancellationBoundaryKind | undefined => {
    if (value === undefined) {
        return undefined;
    }
    if (
        typeof value !== 'string' ||
        !cancellationBoundaryKinds.has(
            value as DesktopBrowserProofCancellationBoundaryKind,
        )
    ) {
        throw new TypeError(
            'cancellationBoundaryKind must be a storage yield or safe boundary.',
        );
    }
    return value as DesktopBrowserProofCancellationBoundaryKind;
};

const executionKinds = new Set<DesktopBrowserProofExecutionKind>([
    'cancelled-generation',
    'deterministic-parity',
    'fresh-generation',
    'refused-generation',
    'replay',
    'resumed-generation',
    'verification',
    'worker-reuse-generation',
]);

const requireExecutionKind = (
    value: unknown,
): DesktopBrowserProofExecutionKind => {
    if (
        typeof value !== 'string' ||
        !executionKinds.has(value as DesktopBrowserProofExecutionKind)
    ) {
        throw new TypeError(
            'executionKind is not a desktop-browser proof execution kind.',
        );
    }
    return value as DesktopBrowserProofExecutionKind;
};

const optionalNonnegativeSafeInteger = (
    record: Readonly<Record<string, unknown>>,
    fieldName: string,
): number | undefined => {
    const value = record[fieldName];
    return value === undefined
        ? undefined
        : requireNonnegativeSafeInteger(value, fieldName);
};

const optionalPositiveSafeInteger = (
    record: Readonly<Record<string, unknown>>,
    fieldName: string,
): number | undefined => {
    const value = record[fieldName];
    return value === undefined
        ? undefined
        : requirePositiveSafeInteger(value, fieldName);
};

const optionalIdentifier = (
    record: Readonly<Record<string, unknown>>,
    fieldName: string,
): string | undefined => {
    const value = record[fieldName];
    return value === undefined
        ? undefined
        : requireNonemptyIdentifier(value, fieldName);
};

const optionalSha512Hex = (
    record: Readonly<Record<string, unknown>>,
    fieldName: string,
): string | undefined => {
    const value = record[fieldName];
    return value === undefined ? undefined : requireSha512Hex(value, fieldName);
};

export const parseDesktopBrowserProofMeasurementRecord = (
    value: unknown,
): DesktopBrowserProofMeasurementRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(
            'The desktop-browser proof measurement must be an object.',
        );
    }
    const record = value as Readonly<Record<string, unknown>>;
    const outputSha512Hex = requireSha512Hex(
        record.outputSha512Hex,
        'outputSha512Hex',
    );
    const canonicalOutputByteLength = requireNonnegativeSafeInteger(
        record.canonicalOutputByteLength,
        'canonicalOutputByteLength',
    );
    if (
        canonicalOutputByteLength === 0 &&
        outputSha512Hex !== emptyCanonicalByteSequenceSha512Hex
    ) {
        throw new TypeError(
            'An absent canonical output must carry the SHA-512 digest of the empty byte sequence.',
        );
    }
    const canonicalInputSha512Hex = requireSha512Hex(
        record.canonicalInputSha512Hex,
        'canonicalInputSha512Hex',
    );
    const suiteId = requireSha512Hex(record.suiteId, 'suiteId');
    const wasmSha256Hex = record.wasmSha256Hex;
    if (
        typeof wasmSha256Hex !== 'string' ||
        !sha256HexPattern.test(wasmSha256Hex)
    ) {
        throw new TypeError(
            'wasmSha256Hex must be a lowercase SHA-256 digest.',
        );
    }
    const startedAtUnixMilliseconds = requireNonnegativeSafeInteger(
        record.startedAtUnixMilliseconds,
        'startedAtUnixMilliseconds',
    );
    const finishedAtUnixMilliseconds = requireNonnegativeSafeInteger(
        record.finishedAtUnixMilliseconds,
        'finishedAtUnixMilliseconds',
    );
    if (finishedAtUnixMilliseconds < startedAtUnixMilliseconds) {
        throw new TypeError(
            'finishedAtUnixMilliseconds precedes startedAtUnixMilliseconds.',
        );
    }
    const wasmLinearMemoryStartByteLength = requirePositiveSafeInteger(
        record.wasmLinearMemoryStartByteLength,
        'wasmLinearMemoryStartByteLength',
    );
    const wasmLinearMemoryEndByteLength = requirePositiveSafeInteger(
        record.wasmLinearMemoryEndByteLength,
        'wasmLinearMemoryEndByteLength',
    );
    const wasmLinearMemoryPeakByteLength = requirePositiveSafeInteger(
        record.wasmLinearMemoryPeakByteLength,
        'wasmLinearMemoryPeakByteLength',
    );
    if (
        wasmLinearMemoryPeakByteLength < wasmLinearMemoryStartByteLength ||
        wasmLinearMemoryPeakByteLength < wasmLinearMemoryEndByteLength
    ) {
        throw new TypeError(
            'wasmLinearMemoryPeakByteLength is below an endpoint observation.',
        );
    }
    const wasmLinearMemoryStartPageCount = requirePositiveSafeInteger(
        record.wasmLinearMemoryStartPageCount,
        'wasmLinearMemoryStartPageCount',
    );
    const wasmLinearMemoryEndPageCount = requirePositiveSafeInteger(
        record.wasmLinearMemoryEndPageCount,
        'wasmLinearMemoryEndPageCount',
    );
    const wasmLinearMemoryPeakPageCount = requirePositiveSafeInteger(
        record.wasmLinearMemoryPeakPageCount,
        'wasmLinearMemoryPeakPageCount',
    );
    if (
        wasmLinearMemoryStartPageCount * wasmPageByteLength !==
            wasmLinearMemoryStartByteLength ||
        wasmLinearMemoryEndPageCount * wasmPageByteLength !==
            wasmLinearMemoryEndByteLength ||
        wasmLinearMemoryPeakPageCount * wasmPageByteLength !==
            wasmLinearMemoryPeakByteLength
    ) {
        throw new TypeError(
            'WebAssembly page counts do not match their byte lengths.',
        );
    }
    const javascriptHeapStartByteLength = requirePositiveSafeInteger(
        record.javascriptHeapStartByteLength,
        'javascriptHeapStartByteLength',
    );
    const javascriptHeapEndByteLength = requirePositiveSafeInteger(
        record.javascriptHeapEndByteLength,
        'javascriptHeapEndByteLength',
    );
    const javascriptHeapPeakByteLength = requirePositiveSafeInteger(
        record.javascriptHeapPeakByteLength,
        'javascriptHeapPeakByteLength',
    );
    if (
        javascriptHeapPeakByteLength < javascriptHeapStartByteLength ||
        javascriptHeapPeakByteLength < javascriptHeapEndByteLength
    ) {
        throw new TypeError(
            'javascriptHeapPeakByteLength is below an endpoint observation.',
        );
    }
    const browserProcessResidentMemoryStartByteLength =
        requirePositiveSafeInteger(
            record.browserProcessResidentMemoryStartByteLength,
            'browserProcessResidentMemoryStartByteLength',
        );
    const browserProcessResidentMemoryEndByteLength =
        requirePositiveSafeInteger(
            record.browserProcessResidentMemoryEndByteLength,
            'browserProcessResidentMemoryEndByteLength',
        );
    const browserProcessResidentMemoryPeakByteLength =
        requirePositiveSafeInteger(
            record.browserProcessResidentMemoryPeakByteLength,
            'browserProcessResidentMemoryPeakByteLength',
        );
    if (
        browserProcessResidentMemoryPeakByteLength <
            browserProcessResidentMemoryStartByteLength ||
        browserProcessResidentMemoryPeakByteLength <
            browserProcessResidentMemoryEndByteLength
    ) {
        throw new TypeError(
            'browserProcessResidentMemoryPeakByteLength is below an endpoint observation.',
        );
    }
    const copiedBufferPeakByteLength = requireNonnegativeSafeInteger(
        record.copiedBufferPeakByteLength,
        'copiedBufferPeakByteLength',
    );
    const externalScratchPeakByteLength = requireNonnegativeSafeInteger(
        record.externalScratchPeakByteLength,
        'externalScratchPeakByteLength',
    );
    const externalScratchReadByteLength = requireNonnegativeSafeInteger(
        record.externalScratchReadByteLength,
        'externalScratchReadByteLength',
    );
    const externalScratchTransactionCount = requireNonnegativeSafeInteger(
        record.externalScratchTransactionCount,
        'externalScratchTransactionCount',
    );
    const externalScratchWriteByteLength = requireNonnegativeSafeInteger(
        record.externalScratchWriteByteLength,
        'externalScratchWriteByteLength',
    );
    if (
        externalScratchTransactionCount === 0 &&
        (externalScratchPeakByteLength !== 0 ||
            externalScratchReadByteLength !== 0 ||
            externalScratchWriteByteLength !== 0)
    ) {
        throw new TypeError(
            'External-scratch bytes require at least one observed transaction.',
        );
    }
    const fullBufferCopiedByteLength = requireNonnegativeSafeInteger(
        record.fullBufferCopiedByteLength,
        'fullBufferCopiedByteLength',
    );
    const fullBufferCopyCount = requireNonnegativeSafeInteger(
        record.fullBufferCopyCount,
        'fullBufferCopyCount',
    );
    if (
        (fullBufferCopyCount === 0) !== (fullBufferCopiedByteLength === 0) ||
        (fullBufferCopyCount === 0) !== (copiedBufferPeakByteLength === 0) ||
        fullBufferCopiedByteLength < copiedBufferPeakByteLength
    ) {
        throw new TypeError(
            'Full-buffer copy count, volume, and peak are inconsistent.',
        );
    }
    const cancellationBoundaryCatalogSha512Hex = optionalSha512Hex(
        record,
        'cancellationBoundaryCatalogSha512Hex',
    );
    const cancellationBoundaryIdentifier = optionalIdentifier(
        record,
        'cancellationBoundaryIdentifier',
    );
    const cancellationBoundaryKind = optionalCancellationBoundaryKind(
        record.cancellationBoundaryKind,
    );
    const cancellationBoundaryOrdinal = optionalPositiveSafeInteger(
        record,
        'cancellationBoundaryOrdinal',
    );
    const declaredSafeBoundaryCount = optionalNonnegativeSafeInteger(
        record,
        'declaredSafeBoundaryCount',
    );
    const declaredStorageYieldBoundaryCount = optionalNonnegativeSafeInteger(
        record,
        'declaredStorageYieldBoundaryCount',
    );
    const declarationFieldCount = [
        cancellationBoundaryCatalogSha512Hex,
        declaredSafeBoundaryCount,
        declaredStorageYieldBoundaryCount,
    ].filter((field) => field !== undefined).length;
    if (declarationFieldCount !== 0 && declarationFieldCount !== 3) {
        throw new TypeError(
            'Cancellation boundary declarations must be complete or absent.',
        );
    }
    const cancellationFieldCount = [
        cancellationBoundaryIdentifier,
        cancellationBoundaryKind,
        cancellationBoundaryOrdinal,
    ].filter((field) => field !== undefined).length;
    if (
        (cancellationFieldCount !== 0 && cancellationFieldCount !== 3) ||
        (cancellationFieldCount === 3 && declarationFieldCount !== 3)
    ) {
        throw new TypeError(
            'Cancellation boundary evidence must be complete and carry its declaration.',
        );
    }
    const deterministicCoinBindingSha512Hex = optionalSha512Hex(
        record,
        'deterministicCoinBindingSha512Hex',
    );
    const nativeReferenceByteLength = optionalPositiveSafeInteger(
        record,
        'nativeReferenceByteLength',
    );
    const nativeReferenceSha512Hex = optionalSha512Hex(
        record,
        'nativeReferenceSha512Hex',
    );
    const parityFieldCount = [
        deterministicCoinBindingSha512Hex,
        nativeReferenceByteLength,
        nativeReferenceSha512Hex,
    ].filter((field) => field !== undefined).length;
    if (parityFieldCount !== 0 && parityFieldCount !== 3) {
        throw new TypeError(
            'Native and WebAssembly deterministic-parity evidence must be complete or absent.',
        );
    }
    const refusalReasonIdentifier = optionalIdentifier(
        record,
        'refusalReasonIdentifier',
    );
    const executionKind = requireExecutionKind(record.executionKind);
    if (
        (executionKind === 'cancelled-generation') !==
        (cancellationFieldCount === 3)
    ) {
        throw new TypeError(
            'Only cancelled-generation evidence must carry one exact cancellation boundary.',
        );
    }
    if (
        (executionKind === 'deterministic-parity') !==
        (parityFieldCount === 3)
    ) {
        throw new TypeError(
            'Only deterministic-parity evidence must carry the complete native reference binding.',
        );
    }
    if (
        (executionKind === 'refused-generation') !==
        (refusalReasonIdentifier !== undefined)
    ) {
        throw new TypeError(
            'Only refused-generation evidence must carry one refusal reason.',
        );
    }
    const resourceAccounting = parseDesktopBrowserProofResourceAccounting(
        record.resourceAccounting,
    );
    if (
        resourceAccounting.kernelStorageRequestCount !==
        externalScratchTransactionCount
    ) {
        throw new TypeError(
            'Kernel storage-request accounting differs from the observed external-scratch transaction count.',
        );
    }

    return Object.freeze({
        browserCacheState: requireCacheState(record.browserCacheState),
        browserProcessResidentMemoryEndByteLength,
        browserProcessResidentMemoryPeakByteLength,
        browserProcessResidentMemoryStartByteLength,
        canonicalInputByteLength: requireNonnegativeSafeInteger(
            record.canonicalInputByteLength,
            'canonicalInputByteLength',
        ),
        canonicalInputSha512Hex,
        canonicalOutputByteLength,
        caseIdentifier: requireNonemptyIdentifier(
            record.caseIdentifier,
            'caseIdentifier',
        ),
        copiedBufferPeakByteLength,
        ...(cancellationBoundaryCatalogSha512Hex === undefined
            ? {}
            : { cancellationBoundaryCatalogSha512Hex }),
        ...(cancellationBoundaryIdentifier === undefined
            ? {}
            : { cancellationBoundaryIdentifier }),
        ...(cancellationBoundaryKind === undefined
            ? {}
            : { cancellationBoundaryKind }),
        ...(cancellationBoundaryOrdinal === undefined
            ? {}
            : { cancellationBoundaryOrdinal }),
        ...(declaredSafeBoundaryCount === undefined
            ? {}
            : { declaredSafeBoundaryCount }),
        ...(declaredStorageYieldBoundaryCount === undefined
            ? {}
            : { declaredStorageYieldBoundaryCount }),
        ...(deterministicCoinBindingSha512Hex === undefined
            ? {}
            : { deterministicCoinBindingSha512Hex }),
        durationMilliseconds: requireFiniteNonnegativeNumber(
            record.durationMilliseconds,
            'durationMilliseconds',
        ),
        executionKind,
        externalScratchPeakByteLength,
        externalScratchReadByteLength,
        externalScratchTransactionCount,
        externalScratchWriteByteLength,
        finishedAtUnixMilliseconds,
        fullBufferCopiedByteLength,
        fullBufferCopyCount,
        observedHostAllocationVolumeByteLength: requireNonnegativeSafeInteger(
            record.observedHostAllocationVolumeByteLength,
            'observedHostAllocationVolumeByteLength',
        ),
        javascriptHeapEndByteLength,
        javascriptHeapPeakByteLength,
        javascriptHeapStartByteLength,
        ...(nativeReferenceByteLength === undefined
            ? {}
            : { nativeReferenceByteLength }),
        ...(nativeReferenceSha512Hex === undefined
            ? {}
            : { nativeReferenceSha512Hex }),
        outputSha512Hex,
        ...(refusalReasonIdentifier === undefined
            ? {}
            : { refusalReasonIdentifier }),
        resourceAccounting,
        retainedResidentPeakByteLength: requireNonnegativeSafeInteger(
            record.retainedResidentPeakByteLength,
            'retainedResidentPeakByteLength',
        ),
        runOrdinal: requirePositiveSafeInteger(record.runOrdinal, 'runOrdinal'),
        suiteId,
        startedAtUnixMilliseconds,
        wasmSha256Hex,
        wasmLinearMemoryEndByteLength,
        wasmLinearMemoryEndPageCount,
        wasmLinearMemoryPeakByteLength,
        wasmLinearMemoryPeakPageCount,
        wasmLinearMemoryStartByteLength,
        wasmLinearMemoryStartPageCount,
        workerInstanceIdentifier: requireNonemptyIdentifier(
            record.workerInstanceIdentifier,
            'workerInstanceIdentifier',
        ),
        workerOperationOrdinal: requirePositiveSafeInteger(
            record.workerOperationOrdinal,
            'workerOperationOrdinal',
        ),
    });
};

const readObservation = (readers: MemoryReaders): MemoryObservation => {
    return {
        browserProcessResidentMemoryByteLength: requirePositiveSafeInteger(
            readers.browserProcessResidentMemoryByteLength(),
            'browserProcessResidentMemoryByteLength',
        ),
        externalScratchByteLength: requireNonnegativeSafeInteger(
            readers.externalScratchByteLength(),
            'externalScratchByteLength',
        ),
        javascriptHeapByteLength: requirePositiveSafeInteger(
            readers.javascriptHeapByteLength(),
            'javascriptHeapByteLength',
        ),
        retainedResidentByteLength: requireNonnegativeSafeInteger(
            readers.retainedResidentByteLength(),
            'retainedResidentByteLength',
        ),
        wasmLinearMemoryByteLength: requirePositiveSafeInteger(
            readers.wasmLinearMemoryByteLength(),
            'wasmLinearMemoryByteLength',
        ),
    };
};

const yieldBrowserTurn = (): Promise<void> =>
    new Promise((resolve) => {
        setTimeout(resolve, 0);
    });

export const beginDesktopBrowserProofMeasurement = (input: {
    browserCacheState: DesktopBrowserProofCacheState;
    caseIdentifier: string;
    /**
     * A dedicated worker can return the parsed record to its owning test and
     * let that one reporter-visible realm emit it. This prevents the same
     * operation from being recorded twice when browser tooling forwards
     * worker console output.
     */
    emitConsoleEvent?: boolean;
    executionKind: DesktopBrowserProofExecutionKind;
    memoryReaders: MemoryReaders;
    runOrdinal: number;
    suiteId: string;
    wasmSha256Hex: string;
    workerInstanceIdentifier: string;
    workerOperationOrdinal: number;
}): DesktopBrowserProofMeasurement => {
    const browserCacheState = requireCacheState(input.browserCacheState);
    const caseIdentifier = requireNonemptyIdentifier(
        input.caseIdentifier,
        'caseIdentifier',
    );
    const executionKind = requireExecutionKind(input.executionKind);
    const runOrdinal = requirePositiveSafeInteger(
        input.runOrdinal,
        'runOrdinal',
    );
    const workerInstanceIdentifier = requireNonemptyIdentifier(
        input.workerInstanceIdentifier,
        'workerInstanceIdentifier',
    );
    const workerOperationOrdinal = requirePositiveSafeInteger(
        input.workerOperationOrdinal,
        'workerOperationOrdinal',
    );
    const suiteId = input.suiteId;
    if (!sha512HexPattern.test(suiteId)) {
        throw new TypeError('suiteId must be a lowercase 64-byte hash.');
    }
    const wasmSha256Hex = input.wasmSha256Hex;
    if (!sha256HexPattern.test(wasmSha256Hex)) {
        throw new TypeError(
            'wasmSha256Hex must be a lowercase SHA-256 digest.',
        );
    }
    const startedAtUnixMilliseconds = Date.now();
    const startedAtHighResolutionMilliseconds = performance.now();
    const start = readObservation(input.memoryReaders);
    let end = start;
    let browserProcessResidentMemoryPeakByteLength =
        start.browserProcessResidentMemoryByteLength;
    let externalScratchPeakByteLength = start.externalScratchByteLength;
    let javascriptHeapPeakByteLength = start.javascriptHeapByteLength;
    let retainedResidentPeakByteLength = start.retainedResidentByteLength;
    let wasmLinearMemoryPeakByteLength = start.wasmLinearMemoryByteLength;
    let finished = false;

    const sample = (): void => {
        if (finished) {
            throw new Error(
                'The desktop-browser proof measurement is already finished.',
            );
        }
        end = readObservation(input.memoryReaders);
        browserProcessResidentMemoryPeakByteLength = Math.max(
            browserProcessResidentMemoryPeakByteLength,
            end.browserProcessResidentMemoryByteLength,
        );
        externalScratchPeakByteLength = Math.max(
            externalScratchPeakByteLength,
            end.externalScratchByteLength,
        );
        retainedResidentPeakByteLength = Math.max(
            retainedResidentPeakByteLength,
            end.retainedResidentByteLength,
        );
        wasmLinearMemoryPeakByteLength = Math.max(
            wasmLinearMemoryPeakByteLength,
            end.wasmLinearMemoryByteLength,
        );
        javascriptHeapPeakByteLength = Math.max(
            javascriptHeapPeakByteLength,
            end.javascriptHeapByteLength,
        );
    };

    return Object.freeze({
        finish: (finishInput) => {
            sample();
            finished = true;
            const finishedAtUnixMilliseconds = Date.now();
            const record = parseDesktopBrowserProofMeasurementRecord({
                browserCacheState,
                browserProcessResidentMemoryEndByteLength:
                    end.browserProcessResidentMemoryByteLength,
                browserProcessResidentMemoryPeakByteLength,
                browserProcessResidentMemoryStartByteLength:
                    start.browserProcessResidentMemoryByteLength,
                canonicalInputByteLength: requireNonnegativeSafeInteger(
                    finishInput.canonicalInputByteLength,
                    'canonicalInputByteLength',
                ),
                canonicalInputSha512Hex: finishInput.canonicalInputSha512Hex,
                canonicalOutputByteLength: requireNonnegativeSafeInteger(
                    finishInput.canonicalOutputByteLength,
                    'canonicalOutputByteLength',
                ),
                caseIdentifier,
                copiedBufferPeakByteLength: requireNonnegativeSafeInteger(
                    finishInput.copiedBufferPeakByteLength,
                    'copiedBufferPeakByteLength',
                ),
                ...(finishInput.cancellationBoundaryCatalogSha512Hex ===
                undefined
                    ? {}
                    : {
                          cancellationBoundaryCatalogSha512Hex:
                              finishInput.cancellationBoundaryCatalogSha512Hex,
                      }),
                ...(finishInput.cancellationBoundaryIdentifier === undefined
                    ? {}
                    : {
                          cancellationBoundaryIdentifier:
                              finishInput.cancellationBoundaryIdentifier,
                      }),
                ...(finishInput.cancellationBoundaryKind === undefined
                    ? {}
                    : {
                          cancellationBoundaryKind:
                              finishInput.cancellationBoundaryKind,
                      }),
                ...(finishInput.cancellationBoundaryOrdinal === undefined
                    ? {}
                    : {
                          cancellationBoundaryOrdinal:
                              finishInput.cancellationBoundaryOrdinal,
                      }),
                ...(finishInput.declaredSafeBoundaryCount === undefined
                    ? {}
                    : {
                          declaredSafeBoundaryCount:
                              finishInput.declaredSafeBoundaryCount,
                      }),
                ...(finishInput.declaredStorageYieldBoundaryCount === undefined
                    ? {}
                    : {
                          declaredStorageYieldBoundaryCount:
                              finishInput.declaredStorageYieldBoundaryCount,
                      }),
                ...(finishInput.deterministicCoinBindingSha512Hex === undefined
                    ? {}
                    : {
                          deterministicCoinBindingSha512Hex:
                              finishInput.deterministicCoinBindingSha512Hex,
                      }),
                durationMilliseconds:
                    performance.now() - startedAtHighResolutionMilliseconds,
                executionKind,
                externalScratchPeakByteLength: Math.max(
                    externalScratchPeakByteLength,
                    requireNonnegativeSafeInteger(
                        finishInput.externalScratchPeakByteLength,
                        'externalScratchPeakByteLength',
                    ),
                ),
                externalScratchReadByteLength:
                    finishInput.externalScratchReadByteLength,
                externalScratchTransactionCount:
                    finishInput.externalScratchTransactionCount,
                externalScratchWriteByteLength:
                    finishInput.externalScratchWriteByteLength,
                finishedAtUnixMilliseconds,
                fullBufferCopiedByteLength:
                    finishInput.fullBufferCopiedByteLength,
                fullBufferCopyCount: finishInput.fullBufferCopyCount,
                observedHostAllocationVolumeByteLength:
                    finishInput.observedHostAllocationVolumeByteLength,
                javascriptHeapEndByteLength: end.javascriptHeapByteLength,
                javascriptHeapPeakByteLength,
                javascriptHeapStartByteLength: start.javascriptHeapByteLength,
                ...(finishInput.nativeReferenceByteLength === undefined
                    ? {}
                    : {
                          nativeReferenceByteLength:
                              finishInput.nativeReferenceByteLength,
                      }),
                ...(finishInput.nativeReferenceSha512Hex === undefined
                    ? {}
                    : {
                          nativeReferenceSha512Hex:
                              finishInput.nativeReferenceSha512Hex,
                      }),
                outputSha512Hex: finishInput.outputSha512Hex,
                ...(finishInput.refusalReasonIdentifier === undefined
                    ? {}
                    : {
                          refusalReasonIdentifier:
                              finishInput.refusalReasonIdentifier,
                      }),
                resourceAccounting: finishInput.resourceAccounting,
                retainedResidentPeakByteLength,
                runOrdinal,
                suiteId,
                startedAtUnixMilliseconds,
                wasmSha256Hex,
                wasmLinearMemoryEndByteLength: end.wasmLinearMemoryByteLength,
                wasmLinearMemoryEndPageCount:
                    end.wasmLinearMemoryByteLength / wasmPageByteLength,
                wasmLinearMemoryPeakByteLength,
                wasmLinearMemoryPeakPageCount:
                    wasmLinearMemoryPeakByteLength / wasmPageByteLength,
                wasmLinearMemoryStartByteLength:
                    start.wasmLinearMemoryByteLength,
                wasmLinearMemoryStartPageCount:
                    start.wasmLinearMemoryByteLength / wasmPageByteLength,
                workerInstanceIdentifier,
                workerOperationOrdinal,
            });
            if (input.emitConsoleEvent !== false) {
                console.info(
                    `${desktopBrowserProofMeasurementConsolePrefix}${JSON.stringify(record)}`,
                );
            }
            return record;
        },
        sample,
        yieldControl: async () => {
            sample();
            await yieldBrowserTurn();
            sample();
        },
    });
};
