import type {
    AuthenticatedCommonProofInputStore,
    CommonProofCanonicalOutputStore,
    CommonProofExternalMemoryReadResult,
    CommonProofExternalMemoryRequest,
    CommonProofExternalMemoryTransactionExecutor,
} from '@sealed-lattice/wasm';

type PrefixReplayExternalMemoryExecutor = Readonly<{
    executeDeterministicPrefixReplayTransaction(
        request: CommonProofExternalMemoryRequest,
    ): Promise<readonly CommonProofExternalMemoryReadResult[]>;
}>;

type ExternalMemoryObjectAccounting = Readonly<{
    appendedByteLength: number;
    exactByteLength: number;
    sealed: boolean;
}>;

export type DesktopBrowserProofResourceAccountingSnapshot = Readonly<{
    copiedBufferPeakByteLength: number;
    externalScratchPeakByteLength: number;
    externalScratchReadByteLength: number;
    externalScratchTransactionCount: number;
    externalScratchWriteByteLength: number;
    fullBufferCopiedByteLength: number;
    fullBufferCopyCount: number;
    observedHostAllocationVolumeByteLength: number;
}>;

export type DesktopBrowserProofResourceAccounting = Readonly<{
    externalScratchByteLength(): number;
    observeFullBufferCopy(byteLength: number): void;
    observeHostAllocation(byteLength: number): void;
    snapshot(): DesktopBrowserProofResourceAccountingSnapshot;
    wrapAuthenticatedInputStore(
        store: AuthenticatedCommonProofInputStore,
    ): AuthenticatedCommonProofInputStore;
    wrapCanonicalOutputStore(
        store: CommonProofCanonicalOutputStore,
    ): CommonProofCanonicalOutputStore;
    wrapExternalMemoryExecutor(
        executor: CommonProofExternalMemoryTransactionExecutor,
    ): CommonProofExternalMemoryTransactionExecutor;
    wrapPrefixReplayExternalMemoryExecutor(
        executor: PrefixReplayExternalMemoryExecutor,
    ): PrefixReplayExternalMemoryExecutor;
}>;

const requireNonnegativeSafeInteger = (
    value: unknown,
    label: string,
): number => {
    if (!Number.isSafeInteger(value) || Number(value) < 0) {
        throw new TypeError(`${label} must be a nonnegative safe integer.`);
    }
    return Number(value);
};

const requirePositiveSafeInteger = (value: unknown, label: string): number => {
    const number = requireNonnegativeSafeInteger(value, label);
    if (number === 0) {
        throw new TypeError(`${label} must be positive.`);
    }
    return number;
};

const safeSum = (
    firstValue: number,
    secondValue: number,
    label: string,
): number => {
    const result = firstValue + secondValue;
    if (!Number.isSafeInteger(result)) {
        throw new TypeError(`${label} exceeds the safe-integer range.`);
    }
    return result;
};

const safeBigIntByteLength = (value: bigint, label: string): number => {
    if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new TypeError(`${label} exceeds the safe-integer range.`);
    }
    return Number(value);
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

type ScratchState = Readonly<{
    appliedTransactionDigests: ReadonlyMap<string, string>;
    byteLength: number;
    objects: ReadonlyMap<number, ExternalMemoryObjectAccounting>;
}>;

const applyExternalMemoryRequest = (
    state: ScratchState,
    request: CommonProofExternalMemoryRequest,
): ScratchState => {
    const transactionIdentifier = request.requestSequence.toString(10);
    const requestDigest = bytesToHex(request.requestDigest);
    if (
        state.appliedTransactionDigests.get(transactionIdentifier) ===
        requestDigest
    ) {
        return state;
    }
    if (state.appliedTransactionDigests.has(transactionIdentifier)) {
        throw new TypeError(
            'External-memory transaction replay changed its request digest.',
        );
    }
    const objects = new Map(state.objects);
    let byteLength = state.byteLength;
    for (const operation of request.operations) {
        switch (operation.operationKind) {
            case 'create': {
                if (objects.has(operation.objectOrdinal)) {
                    throw new TypeError(
                        'External-memory accounting observed duplicate object creation.',
                    );
                }
                const exactByteLength = safeBigIntByteLength(
                    operation.exactByteLength,
                    'External-memory object byte length',
                );
                if (exactByteLength === 0) {
                    throw new TypeError(
                        'External-memory object byte length must be positive.',
                    );
                }
                objects.set(operation.objectOrdinal, {
                    appendedByteLength: 0,
                    exactByteLength,
                    sealed: false,
                });
                byteLength = safeSum(
                    byteLength,
                    exactByteLength,
                    'External scratch byte length',
                );
                break;
            }
            case 'append': {
                const object = objects.get(operation.objectOrdinal);
                if (object === undefined) {
                    throw new TypeError(
                        'External-memory accounting observed an append for an unknown object.',
                    );
                }
                const expectedOffset = safeBigIntByteLength(
                    operation.expectedOffset,
                    'External-memory append offset',
                );
                const appendedByteLength = safeSum(
                    object.appendedByteLength,
                    operation.bytes.byteLength,
                    'External-memory appended byte length',
                );
                if (
                    object.sealed ||
                    expectedOffset !== object.appendedByteLength ||
                    appendedByteLength > object.exactByteLength
                ) {
                    throw new TypeError(
                        'External-memory accounting observed an invalid object append.',
                    );
                }
                objects.set(operation.objectOrdinal, {
                    ...object,
                    appendedByteLength,
                });
                break;
            }
            case 'delete': {
                const object = objects.get(operation.objectOrdinal);
                if (object === undefined) {
                    throw new TypeError(
                        'External-memory accounting observed deletion of an unknown object.',
                    );
                }
                if (!object.sealed) {
                    throw new TypeError(
                        'External-memory accounting observed deletion before object sealing.',
                    );
                }
                byteLength -= object.exactByteLength;
                objects.delete(operation.objectOrdinal);
                break;
            }
            case 'read': {
                const object = objects.get(operation.objectOrdinal);
                const offset = safeBigIntByteLength(
                    operation.offset,
                    'External-memory read offset',
                );
                const end = safeSum(
                    offset,
                    operation.byteLength,
                    'External-memory read end',
                );
                if (
                    object === undefined ||
                    !object.sealed ||
                    end > object.exactByteLength
                ) {
                    throw new TypeError(
                        'External-memory accounting observed an invalid object read.',
                    );
                }
                break;
            }
            case 'seal': {
                const object = objects.get(operation.objectOrdinal);
                if (
                    object === undefined ||
                    object.sealed ||
                    object.appendedByteLength !== object.exactByteLength
                ) {
                    throw new TypeError(
                        'External-memory accounting observed invalid object sealing.',
                    );
                }
                objects.set(operation.objectOrdinal, {
                    ...object,
                    sealed: true,
                });
                break;
            }
        }
    }
    const appliedTransactionDigests = new Map(state.appliedTransactionDigests);
    appliedTransactionDigests.set(transactionIdentifier, requestDigest);
    return Object.freeze({
        appliedTransactionDigests,
        byteLength,
        objects,
    });
};

const requestedScratchWriteByteLength = (
    request: CommonProofExternalMemoryRequest,
): number =>
    request.operations.reduce((byteLength, operation) => {
        const operationByteLength =
            operation.operationKind === 'append'
                ? operation.bytes.byteLength
                : 0;
        return safeSum(
            byteLength,
            operationByteLength,
            'External scratch write byte length',
        );
    }, 0);

export const createDesktopBrowserProofResourceAccounting =
    (): DesktopBrowserProofResourceAccounting => {
        let copiedBufferPeakByteLength = 0;
        let externalScratchPeakByteLength = 0;
        let externalScratchReadByteLength = 0;
        let externalScratchTransactionCount = 0;
        let externalScratchWriteByteLength = 0;
        let fullBufferCopiedByteLength = 0;
        let fullBufferCopyCount = 0;
        let observedHostAllocationVolumeByteLength = 0;
        let scratchState: ScratchState = Object.freeze({
            appliedTransactionDigests: new Map(),
            byteLength: 0,
            objects: new Map(),
        });

        const observeHostAllocation = (byteLengthValue: number): void => {
            const byteLength = requirePositiveSafeInteger(
                byteLengthValue,
                'Observed host allocation byte length',
            );
            observedHostAllocationVolumeByteLength = safeSum(
                observedHostAllocationVolumeByteLength,
                byteLength,
                'Observed host allocation volume',
            );
        };

        const observeFullBufferCopy = (byteLengthValue: number): void => {
            const byteLength = requirePositiveSafeInteger(
                byteLengthValue,
                'Full-buffer copy byte length',
            );
            fullBufferCopyCount = safeSum(
                fullBufferCopyCount,
                1,
                'Full-buffer copy count',
            );
            fullBufferCopiedByteLength = safeSum(
                fullBufferCopiedByteLength,
                byteLength,
                'Full-buffer copy volume',
            );
            copiedBufferPeakByteLength = Math.max(
                copiedBufferPeakByteLength,
                byteLength,
            );
            observeHostAllocation(byteLength);
        };

        const executeTrackedTransaction = async (
            request: CommonProofExternalMemoryRequest,
            executeTransaction: () => Promise<
                readonly CommonProofExternalMemoryReadResult[]
            >,
        ): Promise<readonly CommonProofExternalMemoryReadResult[]> => {
            const nextScratchState = applyExternalMemoryRequest(
                scratchState,
                request,
            );
            const requestedWriteByteLength =
                requestedScratchWriteByteLength(request);
            const readResults = await executeTransaction();
            try {
                const readByteLength = readResults.reduce(
                    (byteLength, result) =>
                        safeSum(
                            byteLength,
                            result.bytes.byteLength,
                            'External scratch read byte length',
                        ),
                    0,
                );
                externalScratchTransactionCount = safeSum(
                    externalScratchTransactionCount,
                    1,
                    'External scratch transaction count',
                );
                externalScratchReadByteLength = safeSum(
                    externalScratchReadByteLength,
                    readByteLength,
                    'External scratch read volume',
                );
                externalScratchWriteByteLength = safeSum(
                    externalScratchWriteByteLength,
                    requestedWriteByteLength,
                    'External scratch write volume',
                );
                scratchState = nextScratchState;
                externalScratchPeakByteLength = Math.max(
                    externalScratchPeakByteLength,
                    scratchState.byteLength,
                );
                for (const readResult of readResults) {
                    if (readResult.bytes.byteLength > 0) {
                        observeFullBufferCopy(readResult.bytes.byteLength);
                    }
                }
                return readResults;
            } catch (error) {
                for (const readResult of readResults) {
                    readResult.bytes.fill(0);
                }
                throw error;
            }
        };

        const wrapExternalMemoryExecutor = (
            executor: CommonProofExternalMemoryTransactionExecutor,
        ): CommonProofExternalMemoryTransactionExecutor =>
            Object.freeze({
                executeTransaction: (request) =>
                    executeTrackedTransaction(request, () =>
                        executor.executeTransaction(request),
                    ),
            });

        const wrapPrefixReplayExternalMemoryExecutor = (
            executor: PrefixReplayExternalMemoryExecutor,
        ): PrefixReplayExternalMemoryExecutor =>
            Object.freeze({
                executeDeterministicPrefixReplayTransaction: (request) =>
                    executeTrackedTransaction(request, () =>
                        executor.executeDeterministicPrefixReplayTransaction(
                            request,
                        ),
                    ),
            });

        const observeReturnedFullBuffer = <Bytes extends Uint8Array>(
            bytes: Bytes,
        ): Bytes => {
            if (bytes.byteLength > 0) {
                observeFullBufferCopy(bytes.byteLength);
            }
            return bytes;
        };

        return Object.freeze({
            externalScratchByteLength: () => scratchState.byteLength,
            observeFullBufferCopy,
            observeHostAllocation,
            snapshot: () =>
                Object.freeze({
                    copiedBufferPeakByteLength,
                    externalScratchPeakByteLength,
                    externalScratchReadByteLength,
                    externalScratchTransactionCount,
                    externalScratchWriteByteLength,
                    fullBufferCopiedByteLength,
                    fullBufferCopyCount,
                    observedHostAllocationVolumeByteLength,
                }),
            wrapAuthenticatedInputStore: (store) =>
                Object.freeze({
                    declaredByteLength: store.declaredByteLength,
                    readCommittedChunk: async (chunkIndex, exactByteLength) =>
                        observeReturnedFullBuffer(
                            await store.readCommittedChunk(
                                chunkIndex,
                                exactByteLength,
                            ),
                        ),
                }),
            wrapCanonicalOutputStore: (store) =>
                Object.freeze({
                    commitChunk: async (chunkIndex, chunkBytes) => {
                        await store.commitChunk(chunkIndex, chunkBytes);
                        if (chunkBytes.byteLength > 0) {
                            observeFullBufferCopy(chunkBytes.byteLength);
                        }
                    },
                    readChunk: async (chunkIndex, exactByteLength) =>
                        observeReturnedFullBuffer(
                            await store.readChunk(chunkIndex, exactByteLength),
                        ),
                }),
            wrapExternalMemoryExecutor,
            wrapPrefixReplayExternalMemoryExecutor,
        });
    };
