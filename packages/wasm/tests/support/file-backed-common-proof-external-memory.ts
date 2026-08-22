import {
    constants as fileSystemConstants,
    copyFile,
    mkdir,
    open,
    rm,
    unlink,
    type FileHandle,
} from 'node:fs/promises';
import path from 'node:path';

import type {
    CommonProofExternalMemoryOperation,
    CommonProofExternalMemoryReadResult,
    CommonProofExternalMemoryRequest,
    CommonProofExternalMemoryTransactionExecutor,
} from '#packages/wasm/src/index';

const runtimeBindingHashByteLength = 64;
const maximumUnsigned64 = 0xffff_ffff_ffff_ffffn;

type StoredObject = {
    currentByteLength: bigint;
    exactByteLength: bigint;
    path: string;
    protection: 'public-integrity' | 'secret-authenticated-encryption';
    sealed: boolean;
};

type FileBackedTransaction = {
    createdPaths: Set<string>;
    declaredByteLength: bigint;
    deletedObjectLifecycleCount: bigint;
    maximumDeclaredByteLength: bigint;
    objects: Map<number, StoredObject>;
    totalReadByteLength: bigint;
    totalWrittenByteLength: bigint;
};

class FileBackedCommonProofTransactionAbortError extends Error {
    public override readonly name =
        'FileBackedCommonProofTransactionAbortError';

    public constructor(
        public readonly operationFailure: unknown,
        public readonly abortFailure: unknown,
    ) {
        super(
            'File-backed common-proof storage failed and could not abort its transaction.',
        );
    }
}

class FileBackedCommonProofTransactionCleanupError extends Error {
    public override readonly name =
        'FileBackedCommonProofTransactionCleanupError';

    public constructor(public readonly cleanupFailures: readonly unknown[]) {
        super(
            'File-backed common-proof storage could not abort its copy-on-write transaction.',
        );
    }
}

export type FileBackedCommonProofExternalMemoryLogicalUsage = Readonly<{
    deletedObjectLifecycleCount: bigint;
    peakStoredByteLength: bigint;
    totalReadByteLength: bigint;
    totalWrittenByteLength: bigint;
    transactionCount: bigint;
}>;

export type FileBackedCommonProofExternalMemoryPhysicalAccounting = Readonly<{
    copyOnWriteByteLength: bigint;
    copyOnWriteCount: bigint;
    currentDeclaredByteLength: bigint;
    liveObjectCount: number;
    maximumDeclaredByteLength: bigint;
    physicalDeleteCount: bigint;
    physicalFileCreateCount: bigint;
    physicalReadByteLength: bigint;
    physicalReadCount: bigint;
    physicalSealCount: bigint;
    physicalWriteByteLength: bigint;
    physicalWriteCount: bigint;
}>;

export type FileBackedCommonProofExternalMemory =
    CommonProofExternalMemoryTransactionExecutor &
        Readonly<{
            close(): Promise<void>;
            copyLogicalUsage(): FileBackedCommonProofExternalMemoryLogicalUsage;
            copyPhysicalAccounting(): FileBackedCommonProofExternalMemoryPhysicalAccounting;
        }>;

const copyStoredObject = (object: StoredObject): StoredObject => ({
    ...object,
});

const copyObjectMap = (
    objects: ReadonlyMap<number, StoredObject>,
): Map<number, StoredObject> =>
    new Map(
        [...objects].map(([objectOrdinal, object]) => [
            objectOrdinal,
            copyStoredObject(object),
        ]),
    );

const byteArraysEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= left[byteIndex] ^ right[byteIndex];
    }
    return difference === 0;
};

const requireSafeByteLength = (value: bigint, label: string): number => {
    const safeValue = Number(value);
    if (
        value < 0n ||
        value > maximumUnsigned64 ||
        !Number.isSafeInteger(safeValue)
    ) {
        throw new RangeError(`${label} is outside the safe byte-length range.`);
    }
    return safeValue;
};

const requireContainedEvidenceDirectory = (directoryPath: string): string => {
    if (!path.isAbsolute(directoryPath)) {
        throw new Error(
            'File-backed common-proof evidence storage requires an absolute directory path.',
        );
    }
    const repositoryTemporaryDirectory = path.resolve(process.cwd(), 'temp');
    const resolvedDirectory = path.resolve(directoryPath);
    const relativeDirectory = path.relative(
        repositoryTemporaryDirectory,
        resolvedDirectory,
    );
    if (
        relativeDirectory === '' ||
        relativeDirectory === '..' ||
        relativeDirectory.startsWith(`..${path.sep}`) ||
        path.isAbsolute(relativeDirectory)
    ) {
        throw new Error(
            'File-backed common-proof evidence storage must be an isolated descendant of the repository temp directory.',
        );
    }
    return resolvedDirectory;
};

const readExact = async (
    file: FileHandle,
    destination: Uint8Array<ArrayBuffer>,
    fileOffset: number,
): Promise<void> => {
    let destinationOffset = 0;
    while (destinationOffset < destination.byteLength) {
        const read = await file.read(
            destination,
            destinationOffset,
            destination.byteLength - destinationOffset,
            fileOffset + destinationOffset,
        );
        if (read.bytesRead === 0) {
            throw new Error(
                'File-backed common-proof storage reached an unexpected end of object.',
            );
        }
        destinationOffset += read.bytesRead;
    }
};

const validateOperationIndices = (
    operations: readonly CommonProofExternalMemoryOperation[],
): void => {
    for (const [operationIndex, operation] of operations.entries()) {
        if (operation.operationIndex !== operationIndex) {
            throw new Error(
                'File-backed common-proof storage received noncanonical operation indices.',
            );
        }
    }
};

/**
 * Opens copy-on-write file custody for one Node development-evidence storage
 * owner. This preserves the exact external-memory transaction lifecycle but
 * is not browser, persistence, restart, or phone evidence.
 */
export const openFileBackedCommonProofExternalMemory = async (input: {
    directoryPath: string;
    runtimeBindingHash: Uint8Array;
}): Promise<FileBackedCommonProofExternalMemory> => {
    const directoryPath = requireContainedEvidenceDirectory(
        input.directoryPath,
    );
    if (
        !(input.runtimeBindingHash instanceof Uint8Array) ||
        input.runtimeBindingHash.byteLength !== runtimeBindingHashByteLength
    ) {
        throw new Error(
            'File-backed common-proof storage requires one exact runtime-binding hash.',
        );
    }
    await mkdir(path.dirname(directoryPath), { recursive: true });
    await mkdir(directoryPath);

    const runtimeBindingHash = input.runtimeBindingHash.slice();
    const knownPaths = new Set<string>();
    let closed = false;
    let failed = false;
    let committedObjects = new Map<number, StoredObject>();
    let currentDeclaredByteLength = 0n;
    let deletedObjectLifecycleCount = 0n;
    let maximumDeclaredByteLength = 0n;
    let nextFileIdentifier = 0n;
    let nextRequestSequence = 1n;
    let totalReadByteLength = 0n;
    let totalWrittenByteLength = 0n;
    let transactionCount = 0n;
    let copyOnWriteByteLength = 0n;
    let copyOnWriteCount = 0n;
    let physicalDeleteCount = 0n;
    let physicalFileCreateCount = 0n;
    let physicalReadByteLength = 0n;
    let physicalReadCount = 0n;
    let physicalSealCount = 0n;
    let physicalWriteByteLength = 0n;
    let physicalWriteCount = 0n;

    const requireOpen = (): void => {
        if (closed) {
            throw new Error(
                'File-backed common-proof storage has already been closed.',
            );
        }
        if (failed) {
            throw new Error(
                'File-backed common-proof storage is retired after an incomplete commit.',
            );
        }
    };

    const nextObjectPath = (objectOrdinal: number): string => {
        const fileIdentifier = nextFileIdentifier;
        nextFileIdentifier += 1n;
        return path.join(
            directoryPath,
            `object-${String(objectOrdinal).padStart(10, '0')}-${fileIdentifier.toString().padStart(12, '0')}.bin`,
        );
    };

    const createEmptyObjectFile = async (
        objectOrdinal: number,
        transaction: FileBackedTransaction,
    ): Promise<string> => {
        const objectPath = nextObjectPath(objectOrdinal);
        const file = await open(objectPath, 'wx');
        await file.close();
        knownPaths.add(objectPath);
        transaction.createdPaths.add(objectPath);
        physicalFileCreateCount += 1n;
        return objectPath;
    };

    const copyObjectForTransaction = async (
        objectOrdinal: number,
        transaction: FileBackedTransaction,
    ): Promise<StoredObject> => {
        const stored = transaction.objects.get(objectOrdinal);
        if (stored === undefined) {
            throw new Error(
                `File-backed common-proof storage cannot copy absent object ${String(objectOrdinal)}.`,
            );
        }
        const committed = committedObjects.get(objectOrdinal);
        if (committed === undefined || stored.path !== committed.path) {
            return stored;
        }
        const copiedPath = nextObjectPath(objectOrdinal);
        await copyFile(
            stored.path,
            copiedPath,
            fileSystemConstants.COPYFILE_EXCL,
        );
        knownPaths.add(copiedPath);
        transaction.createdPaths.add(copiedPath);
        copyOnWriteCount += 1n;
        copyOnWriteByteLength += stored.currentByteLength;
        physicalFileCreateCount += 1n;
        physicalReadCount += 1n;
        physicalReadByteLength += stored.currentByteLength;
        physicalWriteCount += 1n;
        physicalWriteByteLength += stored.currentByteLength;
        stored.path = copiedPath;
        return stored;
    };

    const removeKnownPath = async (objectPath: string): Promise<void> => {
        await unlink(objectPath);
        knownPaths.delete(objectPath);
        physicalDeleteCount += 1n;
    };

    const abortTransaction = async (
        transaction: FileBackedTransaction,
    ): Promise<void> => {
        const cleanupFailures: unknown[] = [];
        for (const createdPath of transaction.createdPaths) {
            try {
                await removeKnownPath(createdPath);
            } catch (error) {
                cleanupFailures.push(error);
            }
        }
        if (cleanupFailures.length > 0) {
            throw new FileBackedCommonProofTransactionCleanupError(
                Object.freeze([...cleanupFailures]),
            );
        }
    };

    const executeOperation = async (
        operation: CommonProofExternalMemoryOperation,
        transaction: FileBackedTransaction,
        readResults: CommonProofExternalMemoryReadResult[],
    ): Promise<void> => {
        switch (operation.operationKind) {
            case 'create': {
                if (
                    operation.exactByteLength <= 0n ||
                    transaction.objects.has(operation.objectOrdinal)
                ) {
                    throw new Error(
                        'File-backed common-proof storage received an invalid duplicate or empty object creation.',
                    );
                }
                const objectPath = await createEmptyObjectFile(
                    operation.objectOrdinal,
                    transaction,
                );
                transaction.objects.set(operation.objectOrdinal, {
                    currentByteLength: 0n,
                    exactByteLength: operation.exactByteLength,
                    path: objectPath,
                    protection: operation.protection,
                    sealed: false,
                });
                transaction.declaredByteLength += operation.exactByteLength;
                transaction.maximumDeclaredByteLength =
                    transaction.maximumDeclaredByteLength >
                    transaction.declaredByteLength
                        ? transaction.maximumDeclaredByteLength
                        : transaction.declaredByteLength;
                break;
            }
            case 'append': {
                const currentStored = transaction.objects.get(
                    operation.objectOrdinal,
                );
                const appendedByteLength = BigInt(operation.bytes.byteLength);
                const followingByteLength =
                    operation.expectedOffset + appendedByteLength;
                if (
                    currentStored === undefined ||
                    operation.bytes.byteLength === 0 ||
                    currentStored.sealed ||
                    currentStored.currentByteLength !==
                        operation.expectedOffset ||
                    followingByteLength > currentStored.exactByteLength
                ) {
                    throw new Error(
                        'File-backed common-proof storage received an invalid append boundary.',
                    );
                }
                const stored = await copyObjectForTransaction(
                    operation.objectOrdinal,
                    transaction,
                );
                const file = await open(stored.path, 'a');
                try {
                    await file.writeFile(operation.bytes);
                } finally {
                    await file.close();
                }
                stored.currentByteLength = followingByteLength;
                transaction.totalWrittenByteLength += appendedByteLength;
                physicalWriteByteLength += appendedByteLength;
                physicalWriteCount += 1n;
                break;
            }
            case 'seal': {
                const stored = transaction.objects.get(operation.objectOrdinal);
                if (
                    stored === undefined ||
                    stored.sealed ||
                    stored.currentByteLength !== stored.exactByteLength
                ) {
                    throw new Error(
                        'File-backed common-proof storage received an invalid seal boundary.',
                    );
                }
                const file = await open(stored.path, 'r+');
                try {
                    await file.sync();
                } finally {
                    await file.close();
                }
                stored.sealed = true;
                physicalSealCount += 1n;
                break;
            }
            case 'read': {
                const stored = transaction.objects.get(operation.objectOrdinal);
                const readEnd = operation.offset + BigInt(operation.byteLength);
                if (
                    stored === undefined ||
                    operation.byteLength <= 0 ||
                    readEnd > stored.currentByteLength
                ) {
                    throw new Error(
                        'File-backed common-proof storage received an invalid read boundary.',
                    );
                }
                const bytes = new Uint8Array(operation.byteLength);
                const file = await open(stored.path, 'r');
                try {
                    await readExact(
                        file,
                        bytes,
                        requireSafeByteLength(
                            operation.offset,
                            'The common-proof object read offset',
                        ),
                    );
                } catch (error) {
                    bytes.fill(0);
                    throw error;
                } finally {
                    await file.close();
                }
                readResults.push(
                    Object.freeze({
                        bytes,
                        objectOrdinal: operation.objectOrdinal,
                        offset: operation.offset,
                        operationIndex: operation.operationIndex,
                    }),
                );
                const readByteLength = BigInt(operation.byteLength);
                transaction.totalReadByteLength += readByteLength;
                physicalReadByteLength += readByteLength;
                physicalReadCount += 1n;
                break;
            }
            case 'delete': {
                const removed = transaction.objects.get(
                    operation.objectOrdinal,
                );
                if (removed === undefined) {
                    throw new Error(
                        'File-backed common-proof storage received an absent object deletion.',
                    );
                }
                transaction.objects.delete(operation.objectOrdinal);
                transaction.declaredByteLength -= removed.exactByteLength;
                transaction.deletedObjectLifecycleCount += 1n;
                break;
            }
        }
    };

    const commitTransaction = async (
        transaction: FileBackedTransaction,
    ): Promise<void> => {
        const retainedPaths = new Set(
            [...transaction.objects.values()].map((object) => object.path),
        );
        const staleCommittedPaths = [...committedObjects.values()]
            .map((object) => object.path)
            .filter((objectPath) => !retainedPaths.has(objectPath));
        const discardedCreatedPaths = [...transaction.createdPaths].filter(
            (objectPath) => !retainedPaths.has(objectPath),
        );
        for (const stalePath of [
            ...staleCommittedPaths,
            ...discardedCreatedPaths,
        ]) {
            await removeKnownPath(stalePath);
        }
        committedObjects = transaction.objects;
        currentDeclaredByteLength = transaction.declaredByteLength;
    };

    const executeTransaction = async (
        request: CommonProofExternalMemoryRequest,
    ): Promise<readonly CommonProofExternalMemoryReadResult[]> => {
        requireOpen();
        if (!byteArraysEqual(request.runtimeBindingHash, runtimeBindingHash)) {
            throw new Error(
                'File-backed common-proof storage received the wrong runtime-binding hash.',
            );
        }
        if (request.requestSequence !== nextRequestSequence) {
            throw new Error(
                'File-backed common-proof storage received the wrong request sequence.',
            );
        }
        if (
            request.operations.length === 0 ||
            request.operations.length > request.maximumOperationCount
        ) {
            throw new Error(
                'File-backed common-proof storage received an invalid operation count.',
            );
        }
        validateOperationIndices(request.operations);
        const transaction: FileBackedTransaction = {
            createdPaths: new Set(),
            declaredByteLength: currentDeclaredByteLength,
            deletedObjectLifecycleCount: 0n,
            maximumDeclaredByteLength,
            objects: copyObjectMap(committedObjects),
            totalReadByteLength: 0n,
            totalWrittenByteLength: 0n,
        };
        const readResults: CommonProofExternalMemoryReadResult[] = [];
        let commitStarted = false;
        try {
            for (const operation of request.operations) {
                await executeOperation(operation, transaction, readResults);
            }
            commitStarted = true;
            await commitTransaction(transaction);
        } catch (operationFailure) {
            for (const readResult of readResults) {
                readResult.bytes.fill(0);
            }
            if (commitStarted) {
                failed = true;
                throw operationFailure;
            }
            try {
                await abortTransaction(transaction);
            } catch (abortFailure) {
                failed = true;
                throw new FileBackedCommonProofTransactionAbortError(
                    operationFailure,
                    abortFailure,
                );
            }
            throw operationFailure;
        }
        deletedObjectLifecycleCount += transaction.deletedObjectLifecycleCount;
        maximumDeclaredByteLength = transaction.maximumDeclaredByteLength;
        totalReadByteLength += transaction.totalReadByteLength;
        totalWrittenByteLength += transaction.totalWrittenByteLength;
        transactionCount += 1n;
        nextRequestSequence += 1n;
        return Object.freeze(readResults);
    };

    const close = async (): Promise<void> => {
        if (closed) {
            return;
        }
        closed = true;
        runtimeBindingHash.fill(0);
        committedObjects.clear();
        currentDeclaredByteLength = 0n;
        knownPaths.clear();
        await rm(directoryPath, { force: true, recursive: true });
    };

    return Object.freeze({
        close,
        copyLogicalUsage: () =>
            Object.freeze({
                deletedObjectLifecycleCount,
                peakStoredByteLength: maximumDeclaredByteLength,
                totalReadByteLength,
                totalWrittenByteLength,
                transactionCount,
            }),
        copyPhysicalAccounting: () =>
            Object.freeze({
                copyOnWriteByteLength,
                copyOnWriteCount,
                currentDeclaredByteLength,
                liveObjectCount: committedObjects.size,
                maximumDeclaredByteLength,
                physicalDeleteCount,
                physicalFileCreateCount,
                physicalReadByteLength,
                physicalReadCount,
                physicalSealCount,
                physicalWriteByteLength,
                physicalWriteCount,
            }),
        executeTransaction,
    });
};
