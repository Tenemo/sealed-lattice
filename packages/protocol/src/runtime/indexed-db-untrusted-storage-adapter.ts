import {
    copyBrowserDeviceWrappingRecord,
    copyBrowserDeviceWrappingState,
    isBrowserDeviceWrappingRetirementTombstone,
    type BrowserDeviceWrappingRecord,
    type BrowserDeviceWrappingState,
    type BrowserDeviceWrappingStateMutation,
    type BrowserDeviceWrappingStateStorage,
} from './browser-action-storage-custody-internal.js';
import type { BrowserActionStorageRootBinding } from './browser-action-storage-custody.js';
import type {
    UntrustedStorageAdapter,
    UntrustedStorageAtomicMutation,
} from './untrusted-storage-transaction-store.js';

const databaseVersion = 1;
const objectStoreName = 'records';
const deviceWrappingRecordKind = 'sealed-lattice-device-wrapping-state';
const deviceWrappingRecordFormatVersion = 2;
const deviceWrappingRetirementRecordKind =
    'sealed-lattice-device-wrapping-retirement';
const deviceWrappingRetirementRecordFormatVersion = 1;
const deviceWrappingMutationIdentifierByteLength = 32;
const storageRootCommitmentByteLength = 64;
const storageNamespacePattern = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;
const deviceWrappingStorageKeyPrefix = 'sealed-lattice-device-wrapping/';
const textEncoder = new TextEncoder();

type IndexedDbUntrustedStorageAdapterErrorCode =
    | 'Closed'
    | 'InvalidMutation'
    | 'OpenFailed'
    | 'SchemaMismatch'
    | 'StrictDurabilityUnavailable'
    | 'TransactionFailed'
    | 'Unavailable';

class IndexedDbUntrustedStorageAdapterError extends Error {
    public readonly code: IndexedDbUntrustedStorageAdapterErrorCode;
    public readonly failureCause: unknown;

    public constructor(
        code: IndexedDbUntrustedStorageAdapterErrorCode,
        message: string,
        failureCause?: unknown,
    ) {
        super(message);
        this.name = 'IndexedDbUntrustedStorageAdapterError';
        this.code = code;
        this.failureCause = failureCause;
    }
}

type IndexedDbUntrustedStorageAdapterConfiguration = Readonly<{
    databaseName: string;
    indexedDbFactory?: IDBFactory;
    keyRangeFactory?: typeof IDBKeyRange;
}>;

type ConnectionState = 'open' | 'closing' | 'closed';

type CopiedExpectedValue = Readonly<{
    key: string;
    value: Uint8Array | undefined;
}>;

type CopiedWrite = Readonly<{
    key: string;
    value: Uint8Array;
}>;

type CopiedMutation = Readonly<{
    expectedValues: readonly CopiedExpectedValue[];
    writes: readonly CopiedWrite[];
    deletes: readonly string[];
}>;

type StoredDeviceWrappingState = Readonly<{
    deviceKey: CryptoKey;
    formatVersion: number;
    mutationIdentifier: Uint8Array;
    recordKind: string;
    storageRootCommitment: Uint8Array;
    wrappedStorageRoot: Uint8Array;
}>;

type StoredDeviceWrappingRetirementTombstone = Readonly<{
    formatVersion: number;
    mutationIdentifier: Uint8Array;
    recordKind: string;
}>;

type StoredDeviceWrappingRecord =
    | StoredDeviceWrappingState
    | StoredDeviceWrappingRetirementTombstone;

const bytesEqual = (
    left: Uint8Array | undefined,
    right: Uint8Array | undefined,
): boolean => {
    if (left === undefined || right === undefined) {
        return left === right;
    }
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        if (left[byteIndex] !== right[byteIndex]) {
            return false;
        }
    }

    return true;
};

const assertDatabaseName = (name: string): void => {
    if (name.length === 0 || name.length > 256) {
        throw new IndexedDbUntrustedStorageAdapterError(
            'OpenFailed',
            'IndexedDB databaseName must contain 1 through 256 characters.',
        );
    }
};

const assertStorageKey = (key: string): void => {
    if (typeof key !== 'string') {
        throw new IndexedDbUntrustedStorageAdapterError(
            'InvalidMutation',
            'IndexedDB storage keys must be strings.',
        );
    }
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const copyBytes = (value: Uint8Array, label: string): Uint8Array => {
    if (!(value instanceof Uint8Array)) {
        throw new IndexedDbUntrustedStorageAdapterError(
            'InvalidMutation',
            `${label} must be a Uint8Array.`,
        );
    }
    try {
        return value.slice();
    } catch (error) {
        throw new IndexedDbUntrustedStorageAdapterError(
            'InvalidMutation',
            `${label} could not be copied.`,
            error,
        );
    }
};

const deriveDeviceWrappingStorageKey = (input: {
    binding: BrowserActionStorageRootBinding;
    namespace: string;
}): string => {
    if (
        input.namespace.length > 64 ||
        !storageNamespacePattern.test(input.namespace)
    ) {
        throw new IndexedDbUntrustedStorageAdapterError(
            'InvalidMutation',
            'Device-wrapping storage namespace must be lowercase kebab-case with at most 64 characters.',
        );
    }
    const bindingParts: readonly [string, Uint8Array][] = [
        ['suite identifier', input.binding.suiteId],
        ['ceremony-context hash', input.binding.ceremonyContextHash],
        ['action-context hash', input.binding.actionContextHash],
        ['participant identity', input.binding.participantId],
    ];
    const canonicalBinding = bindingParts.map(([label, value]) => {
        const copiedValue = copyBytes(value, label);
        if (copiedValue.byteLength !== storageRootCommitmentByteLength) {
            throw new IndexedDbUntrustedStorageAdapterError(
                'InvalidMutation',
                `${label} must contain exactly ${storageRootCommitmentByteLength} bytes.`,
            );
        }

        return bytesToHex(copiedValue);
    });

    return `${deviceWrappingStorageKeyPrefix}${input.namespace}/${canonicalBinding.join('/')}`;
};

const copyStoredBytes = (value: unknown): Uint8Array => {
    if (!(value instanceof Uint8Array)) {
        throw new IndexedDbUntrustedStorageAdapterError(
            'TransactionFailed',
            'IndexedDB contained a value that is not a Uint8Array.',
        );
    }
    try {
        return value.slice();
    } catch (error) {
        throw new IndexedDbUntrustedStorageAdapterError(
            'TransactionFailed',
            'IndexedDB returned bytes that could not be copied.',
            error,
        );
    }
};

const copyDeviceWrappingMutationIdentifier = (
    value: Uint8Array | undefined,
): Uint8Array | undefined => {
    if (value === undefined) {
        return undefined;
    }
    const copy = copyBytes(value, 'device-wrapping mutation identifier');
    if (copy.byteLength !== deviceWrappingMutationIdentifierByteLength) {
        throw new IndexedDbUntrustedStorageAdapterError(
            'InvalidMutation',
            `device-wrapping mutation identifier must contain exactly ${deviceWrappingMutationIdentifierByteLength} bytes.`,
        );
    }

    return copy;
};

const copyDeviceWrappingStateForWrite = (
    value: BrowserDeviceWrappingState,
): StoredDeviceWrappingState => {
    try {
        const copy = copyBrowserDeviceWrappingState(value, 'InvalidState');

        return {
            deviceKey: copy.deviceKey,
            formatVersion: deviceWrappingRecordFormatVersion,
            mutationIdentifier: copy.mutationIdentifier,
            recordKind: deviceWrappingRecordKind,
            storageRootCommitment: copy.storageRootCommitment,
            wrappedStorageRoot: copy.wrappedStorageRoot,
        };
    } catch (error) {
        throw new IndexedDbUntrustedStorageAdapterError(
            'InvalidMutation',
            'The proposed device-wrapping state is invalid.',
            error,
        );
    }
};

const copyDeviceWrappingRecordForWrite = (
    value: BrowserDeviceWrappingRecord,
): StoredDeviceWrappingRecord => {
    if (isBrowserDeviceWrappingRetirementTombstone(value)) {
        const copy = copyBrowserDeviceWrappingRecord(value, 'InvalidState');
        if (!isBrowserDeviceWrappingRetirementTombstone(copy)) {
            throw new IndexedDbUntrustedStorageAdapterError(
                'InvalidMutation',
                'The proposed retirement tombstone changed kind while being copied.',
            );
        }
        return {
            formatVersion: deviceWrappingRetirementRecordFormatVersion,
            mutationIdentifier: copy.mutationIdentifier,
            recordKind: deviceWrappingRetirementRecordKind,
        };
    }
    return copyDeviceWrappingStateForWrite(value);
};

const copyStoredDeviceWrappingState = (
    value: unknown,
): BrowserDeviceWrappingState => {
    try {
        if (typeof value !== 'object' || value === null) {
            throw new Error('stored value is not an object');
        }
        const storedValue = value as StoredDeviceWrappingState;
        if (
            storedValue.recordKind !== deviceWrappingRecordKind ||
            storedValue.formatVersion !== deviceWrappingRecordFormatVersion
        ) {
            throw new Error(
                'stored value has the wrong record kind or version',
            );
        }

        return copyBrowserDeviceWrappingState(storedValue, 'InvalidState');
    } catch (error) {
        throw new IndexedDbUntrustedStorageAdapterError(
            'TransactionFailed',
            'IndexedDB contained a malformed device-wrapping state.',
            error,
        );
    }
};

const copyStoredDeviceWrappingRecord = (
    value: unknown,
): BrowserDeviceWrappingRecord => {
    if (
        typeof value === 'object' &&
        value !== null &&
        (value as Partial<StoredDeviceWrappingRetirementTombstone>)
            .recordKind === deviceWrappingRetirementRecordKind
    ) {
        const storedValue = value as StoredDeviceWrappingRetirementTombstone;
        try {
            if (
                storedValue.formatVersion !==
                deviceWrappingRetirementRecordFormatVersion
            ) {
                throw new Error(
                    'stored retirement tombstone has the wrong version or state',
                );
            }
            const copiedRecord = copyBrowserDeviceWrappingRecord(
                {
                    mutationIdentifier: storedValue.mutationIdentifier,
                    recordKind: 'retirementTombstone',
                },
                'InvalidState',
            );
            if (!isBrowserDeviceWrappingRetirementTombstone(copiedRecord)) {
                throw new Error(
                    'stored retirement tombstone changed kind while being copied',
                );
            }
            return copiedRecord;
        } catch (error) {
            throw new IndexedDbUntrustedStorageAdapterError(
                'TransactionFailed',
                'IndexedDB contained a malformed device-wrapping retirement tombstone.',
                error,
            );
        }
    }
    return copyStoredDeviceWrappingState(value);
};

const copyAndValidateMutation = (
    mutation: UntrustedStorageAtomicMutation,
): CopiedMutation => {
    const expectedKeys = new Set<string>();
    const expectedValues = mutation.expectedValues.map((expectedValue) => {
        assertStorageKey(expectedValue.key);
        if (expectedKeys.has(expectedValue.key)) {
            throw new IndexedDbUntrustedStorageAdapterError(
                'InvalidMutation',
                'Atomic mutation contains a duplicate expected-value key.',
            );
        }
        expectedKeys.add(expectedValue.key);

        return {
            key: expectedValue.key,
            value:
                expectedValue.value === undefined
                    ? undefined
                    : copyBytes(expectedValue.value, 'atomic expected value'),
        };
    });
    const writeKeys = new Set<string>();
    const writes = mutation.writes.map((write) => {
        assertStorageKey(write.key);
        if (writeKeys.has(write.key)) {
            throw new IndexedDbUntrustedStorageAdapterError(
                'InvalidMutation',
                'Atomic mutation contains a duplicate write key.',
            );
        }
        writeKeys.add(write.key);

        return {
            key: write.key,
            value: copyBytes(write.value, 'atomic write value'),
        };
    });
    const deleteKeys = new Set<string>();
    const deletes = mutation.deletes.map((key) => {
        assertStorageKey(key);
        if (deleteKeys.has(key)) {
            throw new IndexedDbUntrustedStorageAdapterError(
                'InvalidMutation',
                'Atomic mutation contains a duplicate delete key.',
            );
        }
        if (writeKeys.has(key)) {
            throw new IndexedDbUntrustedStorageAdapterError(
                'InvalidMutation',
                'Atomic mutation cannot write and delete the same key.',
            );
        }
        deleteKeys.add(key);

        return key;
    });

    return { expectedValues, writes, deletes };
};

const copyAndValidateUnreferencedObjectDeletion = (input: {
    indexPrefix: string;
    objectKeys: readonly string[];
}): Readonly<{ indexPrefix: string; objectKeys: readonly string[] }> => {
    assertStorageKey(input.indexPrefix);
    if (input.indexPrefix.length === 0) {
        throw new IndexedDbUntrustedStorageAdapterError(
            'InvalidMutation',
            'The unreferenced-object index prefix must be nonempty.',
        );
    }
    const uniqueObjectKeys = new Set<string>();
    const objectKeys = input.objectKeys.map((objectKey) => {
        assertStorageKey(objectKey);
        if (objectKey.length === 0 || uniqueObjectKeys.has(objectKey)) {
            throw new IndexedDbUntrustedStorageAdapterError(
                'InvalidMutation',
                'Unreferenced-object deletion keys must be nonempty and unique.',
            );
        }
        uniqueObjectKeys.add(objectKey);
        return objectKey;
    });

    return { indexPrefix: input.indexPrefix, objectKeys };
};

const openDatabase = async (
    indexedDbFactory: IDBFactory,
    name: string,
): Promise<IDBDatabase> =>
    new Promise<IDBDatabase>((resolve, reject) => {
        let openRequest: IDBOpenDBRequest;
        try {
            openRequest = indexedDbFactory.open(name, databaseVersion);
        } catch (error) {
            reject(
                new IndexedDbUntrustedStorageAdapterError(
                    'OpenFailed',
                    'IndexedDB database open failed before a request was created.',
                    error,
                ),
            );
            return;
        }

        let settled = false;
        let upgradeFailure: unknown;
        openRequest.addEventListener('upgradeneeded', (event) => {
            try {
                if (event.oldVersion !== 0) {
                    throw new IndexedDbUntrustedStorageAdapterError(
                        'SchemaMismatch',
                        'IndexedDB requires an unsupported schema upgrade.',
                    );
                }
                if (openRequest.result.objectStoreNames.length !== 0) {
                    throw new IndexedDbUntrustedStorageAdapterError(
                        'SchemaMismatch',
                        'New IndexedDB database unexpectedly contains object stores.',
                    );
                }
                openRequest.result.createObjectStore(objectStoreName);
            } catch (error) {
                upgradeFailure = error;
                try {
                    openRequest.transaction?.abort();
                } catch (abortError) {
                    upgradeFailure = new IndexedDbUntrustedStorageAdapterError(
                        'OpenFailed',
                        'IndexedDB schema creation and upgrade abort both failed.',
                        [error, abortError],
                    );
                }
            }
        });
        openRequest.addEventListener('blocked', () => {
            if (settled) {
                return;
            }
            settled = true;
            reject(
                new IndexedDbUntrustedStorageAdapterError(
                    'OpenFailed',
                    'IndexedDB database open was blocked by another connection.',
                ),
            );
        });
        openRequest.addEventListener('error', () => {
            if (settled) {
                return;
            }
            settled = true;
            reject(
                upgradeFailure instanceof Error
                    ? upgradeFailure
                    : new IndexedDbUntrustedStorageAdapterError(
                          'OpenFailed',
                          'IndexedDB database open request failed.',
                          upgradeFailure ?? openRequest.error,
                      ),
            );
        });
        openRequest.addEventListener('success', () => {
            if (settled) {
                openRequest.result.close();
                return;
            }
            settled = true;
            resolve(openRequest.result);
        });
    });

export class IndexedDbUntrustedStorageAdapter implements UntrustedStorageAdapter {
    readonly #database: IDBDatabase;
    readonly #keyRangeFactory: typeof IDBKeyRange;
    #activeOperationCount = 0;
    readonly #activeTransactions = new Set<IDBTransaction>();
    #connectionState: ConnectionState = 'open';
    #databaseCloseRequested = false;
    readonly #closedPromise: Promise<void>;
    readonly #resolveClosedPromise: () => void;

    private constructor(
        database: IDBDatabase,
        keyRangeFactory: typeof IDBKeyRange,
    ) {
        this.#database = database;
        this.#keyRangeFactory = keyRangeFactory;
        let resolveClosedPromise: (() => void) | undefined;
        this.#closedPromise = new Promise<void>((resolve) => {
            resolveClosedPromise = resolve;
        });
        if (resolveClosedPromise === undefined) {
            throw new IndexedDbUntrustedStorageAdapterError(
                'OpenFailed',
                'IndexedDB close-state initialization failed.',
            );
        }
        this.#resolveClosedPromise = resolveClosedPromise;
        this.#database.addEventListener('versionchange', () => {
            this.#beginForcedClose(false);
        });
        this.#database.addEventListener('close', () => {
            this.#databaseCloseRequested = true;
            this.#beginForcedClose(true);
        });
    }

    public static async open(
        configuration: IndexedDbUntrustedStorageAdapterConfiguration,
    ): Promise<IndexedDbUntrustedStorageAdapter> {
        assertDatabaseName(configuration.databaseName);
        const indexedDbFactory =
            configuration.indexedDbFactory ?? globalThis.indexedDB;
        const keyRangeFactory =
            configuration.keyRangeFactory ?? globalThis.IDBKeyRange;
        if (indexedDbFactory === undefined || keyRangeFactory === undefined) {
            throw new IndexedDbUntrustedStorageAdapterError(
                'Unavailable',
                'IndexedDB and IDBKeyRange are required for browser storage.',
            );
        }
        const database = await openDatabase(
            indexedDbFactory,
            configuration.databaseName,
        );
        const adapter = new IndexedDbUntrustedStorageAdapter(
            database,
            keyRangeFactory,
        );
        try {
            await adapter.#verifySchema();
            await adapter.#verifyStrictDurability();
        } catch (error) {
            await adapter.close();
            throw error;
        }

        return adapter;
    }

    public async read(key: string): Promise<Uint8Array | undefined> {
        assertStorageKey(key);
        return this.#withOpenConnection(async (database) => {
            const transaction = this.#trackTransaction(
                database.transaction(objectStoreName, 'readonly'),
            );
            const objectStore = transaction.objectStore(objectStoreName);
            let operationFailure: unknown;
            let result: Uint8Array | undefined;
            const completion = this.#waitForTransaction(
                transaction,
                'IndexedDB read',
                () => operationFailure,
            );
            let request: IDBRequest<IDBCursorWithValue | null>;
            try {
                request = objectStore.openCursor(key);
            } catch (error) {
                operationFailure = error;
                return this.#rejectAfterSynchronousRequestFailure({
                    completion,
                    operation: 'IndexedDB read',
                    operationFailure: error,
                    transaction,
                });
            }
            request.addEventListener('success', () => {
                try {
                    const cursor = request.result;
                    if (cursor === null) {
                        result = undefined;
                        return;
                    }
                    if (cursor.key !== key) {
                        throw new IndexedDbUntrustedStorageAdapterError(
                            'TransactionFailed',
                            'IndexedDB exact-key read returned a different key.',
                        );
                    }
                    result = copyStoredBytes(cursor.value);
                } catch (error) {
                    operationFailure = error;
                    this.#abortAfterOperationFailure(transaction, error);
                }
            });
            request.addEventListener('error', () => {
                operationFailure ??= request.error;
            });
            await completion;
            if (operationFailure !== undefined) {
                throw this.#transactionFailure(
                    'IndexedDB read',
                    operationFailure,
                );
            }

            return result;
        });
    }

    public async write(key: string, value: Uint8Array): Promise<void> {
        assertStorageKey(key);
        const copiedValue = copyBytes(value, 'IndexedDB write value');
        await this.#withOpenConnection(async (database) => {
            const transaction = this.#strictReadwriteTransaction(database);
            let operationFailure: unknown;
            const completion = this.#waitForTransaction(
                transaction,
                'IndexedDB write',
                () => operationFailure,
            );
            let request: IDBRequest<IDBValidKey>;
            try {
                request = transaction
                    .objectStore(objectStoreName)
                    .put(copiedValue, key);
            } catch (error) {
                operationFailure = error;
                return this.#rejectAfterSynchronousRequestFailure({
                    completion,
                    operation: 'IndexedDB write',
                    operationFailure: error,
                    transaction,
                });
            }
            request.addEventListener('error', () => {
                operationFailure ??= request.error;
            });
            await completion;
        });
    }

    public async delete(key: string): Promise<void> {
        assertStorageKey(key);
        await this.#withOpenConnection(async (database) => {
            const transaction = this.#strictReadwriteTransaction(database);
            let operationFailure: unknown;
            const completion = this.#waitForTransaction(
                transaction,
                'IndexedDB delete',
                () => operationFailure,
            );
            let request: IDBRequest<undefined>;
            try {
                request = transaction.objectStore(objectStoreName).delete(key);
            } catch (error) {
                operationFailure = error;
                return this.#rejectAfterSynchronousRequestFailure({
                    completion,
                    operation: 'IndexedDB delete',
                    operationFailure: error,
                    transaction,
                });
            }
            request.addEventListener('error', () => {
                operationFailure ??= request.error;
            });
            await completion;
        });
    }

    public async listKeys(prefix: string): Promise<readonly string[]> {
        assertStorageKey(prefix);
        return this.#withOpenConnection(async (database) => {
            const transaction = this.#trackTransaction(
                database.transaction(objectStoreName, 'readonly'),
            );
            const objectStore = transaction.objectStore(objectStoreName);
            const keys: string[] = [];
            let operationFailure: unknown;
            const completion = this.#waitForTransaction(
                transaction,
                'IndexedDB prefix listing',
                () => operationFailure,
            );
            let request: IDBRequest<IDBCursor | null>;
            try {
                request = objectStore.openKeyCursor(
                    this.#keyRangeFactory.lowerBound(prefix),
                );
            } catch (error) {
                operationFailure = error;
                return this.#rejectAfterSynchronousRequestFailure({
                    completion,
                    operation: 'IndexedDB prefix listing',
                    operationFailure: error,
                    transaction,
                });
            }
            request.addEventListener('success', () => {
                try {
                    const cursor = request.result;
                    if (cursor === null) {
                        return;
                    }
                    if (typeof cursor.key !== 'string') {
                        throw new IndexedDbUntrustedStorageAdapterError(
                            'TransactionFailed',
                            'IndexedDB object store contains a non-string key.',
                        );
                    }
                    if (!cursor.key.startsWith(prefix)) {
                        return;
                    }
                    keys.push(cursor.key);
                    cursor.continue();
                } catch (error) {
                    operationFailure = error;
                    this.#abortAfterOperationFailure(transaction, error);
                }
            });
            request.addEventListener('error', () => {
                operationFailure ??= request.error;
            });
            await completion;
            if (operationFailure !== undefined) {
                throw this.#transactionFailure(
                    'IndexedDB prefix listing',
                    operationFailure,
                );
            }

            return keys;
        });
    }

    public async deleteUnreferencedObjects(input: {
        indexPrefix: string;
        objectKeys: readonly string[];
    }): Promise<boolean> {
        const copiedInput = copyAndValidateUnreferencedObjectDeletion(input);
        if (copiedInput.objectKeys.length === 0) {
            return true;
        }
        const encodedObjectKeys = copiedInput.objectKeys.map((objectKey) =>
            textEncoder.encode(objectKey),
        );
        return this.#withOpenConnection(async (database) => {
            const transaction = this.#strictReadwriteTransaction(database);
            const objectStore = transaction.objectStore(objectStoreName);

            return new Promise<boolean>((resolve, reject) => {
                let conflictDetected = false;
                let operationFailure: unknown;
                const rejectTransaction = (error: unknown): void => {
                    reject(
                        this.#transactionFailure(
                            'IndexedDB unreferenced-object deletion',
                            error,
                        ),
                    );
                };
                transaction.addEventListener(
                    'complete',
                    () => {
                        if (
                            conflictDetected ||
                            operationFailure !== undefined
                        ) {
                            rejectTransaction(
                                operationFailure ??
                                    new IndexedDbUntrustedStorageAdapterError(
                                        'TransactionFailed',
                                        'IndexedDB committed referenced-object deletion after an abort was requested.',
                                    ),
                            );
                            return;
                        }
                        resolve(true);
                    },
                    { once: true },
                );
                transaction.addEventListener(
                    'abort',
                    () => {
                        if (
                            conflictDetected &&
                            operationFailure === undefined
                        ) {
                            resolve(false);
                            return;
                        }
                        rejectTransaction(
                            operationFailure ?? transaction.error,
                        );
                    },
                    { once: true },
                );
                const failOperation = (error: unknown): void => {
                    operationFailure ??= error;
                    try {
                        transaction.abort();
                    } catch (abortError) {
                        operationFailure =
                            new IndexedDbUntrustedStorageAdapterError(
                                'TransactionFailed',
                                'IndexedDB unreferenced-object deletion and transaction abort both failed.',
                                [operationFailure, abortError],
                            );
                    }
                };
                const queueDeletes = (): void => {
                    try {
                        for (const objectKey of copiedInput.objectKeys) {
                            const deleteRequest = objectStore.delete(objectKey);
                            deleteRequest.addEventListener('error', () => {
                                operationFailure ??= deleteRequest.error;
                            });
                        }
                    } catch (error) {
                        failOperation(error);
                    }
                };
                let listingRequest: IDBRequest<IDBCursorWithValue | null>;
                try {
                    listingRequest = objectStore.openCursor(
                        this.#keyRangeFactory.lowerBound(
                            copiedInput.indexPrefix,
                        ),
                    );
                } catch (error) {
                    failOperation(error);
                    return;
                }
                listingRequest.addEventListener('success', () => {
                    try {
                        const cursor = listingRequest.result;
                        if (
                            cursor === null ||
                            typeof cursor.key !== 'string' ||
                            !cursor.key.startsWith(copiedInput.indexPrefix)
                        ) {
                            queueDeletes();
                            return;
                        }
                        const indexValue = copyStoredBytes(cursor.value);
                        if (
                            encodedObjectKeys.some((objectKey) =>
                                bytesEqual(indexValue, objectKey),
                            )
                        ) {
                            conflictDetected = true;
                            try {
                                transaction.abort();
                            } catch (error) {
                                conflictDetected = false;
                                operationFailure = error;
                            }
                            return;
                        }
                        cursor.continue();
                    } catch (error) {
                        failOperation(error);
                    }
                });
                listingRequest.addEventListener('error', () => {
                    operationFailure ??= listingRequest.error;
                });
            });
        });
    }

    public async applyAtomicMutation(
        mutation: UntrustedStorageAtomicMutation,
    ): Promise<boolean> {
        const copiedMutation = copyAndValidateMutation(mutation);
        return this.#withOpenConnection(async (database) => {
            const transaction = this.#strictReadwriteTransaction(database);
            const objectStore = transaction.objectStore(objectStoreName);

            return new Promise<boolean>((resolve, reject) => {
                let conflictDetected = false;
                let operationFailure: unknown;
                let remainingExpectedValueCount =
                    copiedMutation.expectedValues.length;
                const observedValues = new Map<
                    string,
                    Uint8Array | undefined
                >();

                const rejectTransaction = (error: unknown): void => {
                    reject(
                        this.#transactionFailure(
                            'IndexedDB atomic mutation',
                            error,
                        ),
                    );
                };
                transaction.addEventListener(
                    'complete',
                    () => {
                        if (
                            conflictDetected ||
                            operationFailure !== undefined
                        ) {
                            rejectTransaction(
                                operationFailure ??
                                    new IndexedDbUntrustedStorageAdapterError(
                                        'TransactionFailed',
                                        'IndexedDB committed a transaction after an abort was requested.',
                                    ),
                            );
                            return;
                        }
                        resolve(true);
                    },
                    { once: true },
                );
                transaction.addEventListener(
                    'abort',
                    () => {
                        if (
                            conflictDetected &&
                            operationFailure === undefined
                        ) {
                            resolve(false);
                            return;
                        }
                        rejectTransaction(
                            operationFailure ?? transaction.error,
                        );
                    },
                    { once: true },
                );

                const noteRequestFailure = (request: IDBRequest): void => {
                    if (!conflictDetected) {
                        operationFailure ??= request.error;
                    }
                };
                const queueMutations = (): void => {
                    try {
                        for (const key of copiedMutation.deletes) {
                            const request = objectStore.delete(key);
                            request.addEventListener('error', () => {
                                noteRequestFailure(request);
                            });
                        }
                        for (const write of copiedMutation.writes) {
                            const request = objectStore.put(
                                write.value,
                                write.key,
                            );
                            request.addEventListener('error', () => {
                                noteRequestFailure(request);
                            });
                        }
                    } catch (error) {
                        operationFailure = error;
                        this.#abortAfterOperationFailure(transaction, error);
                    }
                };
                const compareAndContinue = (): void => {
                    if (remainingExpectedValueCount !== 0) {
                        return;
                    }
                    const matches = copiedMutation.expectedValues.every(
                        (expectedValue) =>
                            bytesEqual(
                                observedValues.get(expectedValue.key),
                                expectedValue.value,
                            ),
                    );
                    if (!matches) {
                        conflictDetected = true;
                        try {
                            transaction.abort();
                        } catch (error) {
                            conflictDetected = false;
                            operationFailure = error;
                        }
                        return;
                    }
                    queueMutations();
                };

                if (remainingExpectedValueCount === 0) {
                    queueMutations();
                    return;
                }
                for (const expectedValue of copiedMutation.expectedValues) {
                    let request: IDBRequest<IDBCursorWithValue | null>;
                    try {
                        request = objectStore.openCursor(expectedValue.key);
                    } catch (error) {
                        operationFailure = error;
                        this.#abortAfterOperationFailure(transaction, error);
                        return;
                    }
                    request.addEventListener('success', () => {
                        try {
                            const cursor = request.result;
                            if (
                                cursor !== null &&
                                cursor.key !== expectedValue.key
                            ) {
                                throw new IndexedDbUntrustedStorageAdapterError(
                                    'TransactionFailed',
                                    'IndexedDB exact-key comparison returned a different key.',
                                );
                            }
                            observedValues.set(
                                expectedValue.key,
                                cursor === null
                                    ? undefined
                                    : copyStoredBytes(cursor.value),
                            );
                            remainingExpectedValueCount -= 1;
                            compareAndContinue();
                        } catch (error) {
                            operationFailure = error;
                            this.#abortAfterOperationFailure(
                                transaction,
                                error,
                            );
                        }
                    });
                    request.addEventListener('error', () => {
                        noteRequestFailure(request);
                    });
                }
            });
        });
    }

    public createDeviceWrappingStateStorage(input: {
        binding: BrowserActionStorageRootBinding;
        namespace: string;
    }): BrowserDeviceWrappingStateStorage {
        const storageKey = deriveDeviceWrappingStorageKey(input);

        return Object.freeze({
            readState: () => this.#readDeviceWrappingState(storageKey),
            compareAndSwapState: (mutation) =>
                this.#compareAndSwapDeviceWrappingState(storageKey, mutation),
        });
    }

    public close(): Promise<void> {
        if (this.#connectionState === 'open') {
            this.#connectionState = 'closing';
            this.#finishCloseIfIdle();
        }

        return this.#closedPromise;
    }

    async #readDeviceWrappingState(
        storageKey: string,
    ): Promise<BrowserDeviceWrappingRecord | undefined> {
        return this.#withOpenConnection(async (database) => {
            const transaction = this.#trackTransaction(
                database.transaction(objectStoreName, 'readonly'),
            );
            const objectStore = transaction.objectStore(objectStoreName);
            let operationFailure: unknown;
            let result: BrowserDeviceWrappingRecord | undefined;
            const completion = this.#waitForTransaction(
                transaction,
                'IndexedDB device-wrapping read',
                () => operationFailure,
            );
            let request: IDBRequest<IDBCursorWithValue | null>;
            try {
                request = objectStore.openCursor(storageKey);
            } catch (error) {
                operationFailure = error;
                return this.#rejectAfterSynchronousRequestFailure({
                    completion,
                    operation: 'IndexedDB device-wrapping read',
                    operationFailure: error,
                    transaction,
                });
            }
            request.addEventListener('success', () => {
                try {
                    const cursor = request.result;
                    if (cursor === null) {
                        result = undefined;
                        return;
                    }
                    if (cursor.key !== storageKey) {
                        throw new IndexedDbUntrustedStorageAdapterError(
                            'TransactionFailed',
                            'IndexedDB device-wrapping read returned a different key.',
                        );
                    }
                    result = copyStoredDeviceWrappingRecord(cursor.value);
                } catch (error) {
                    operationFailure = error;
                    this.#abortAfterOperationFailure(transaction, error);
                }
            });
            request.addEventListener('error', () => {
                operationFailure ??= request.error;
            });
            await completion;
            if (operationFailure !== undefined) {
                throw this.#transactionFailure(
                    'IndexedDB device-wrapping read',
                    operationFailure,
                );
            }

            return result;
        });
    }

    async #compareAndSwapDeviceWrappingState(
        storageKey: string,
        mutation: BrowserDeviceWrappingStateMutation,
    ): Promise<boolean> {
        const expectedMutationIdentifier = copyDeviceWrappingMutationIdentifier(
            mutation.expectedMutationIdentifier,
        );
        const replacement =
            mutation.replacement === undefined
                ? undefined
                : copyDeviceWrappingRecordForWrite(mutation.replacement);
        if (
            expectedMutationIdentifier !== undefined &&
            replacement !== undefined &&
            bytesEqual(
                expectedMutationIdentifier,
                replacement.mutationIdentifier,
            )
        ) {
            throw new IndexedDbUntrustedStorageAdapterError(
                'InvalidMutation',
                'Device-wrapping replacement must use a fresh mutation identifier.',
            );
        }

        return this.#withOpenConnection(async (database) => {
            const transaction = this.#strictReadwriteTransaction(database);
            const objectStore = transaction.objectStore(objectStoreName);

            return new Promise<boolean>((resolve, reject) => {
                let conflictDetected = false;
                let operationFailure: unknown;
                const rejectTransaction = (error: unknown): void => {
                    reject(
                        this.#transactionFailure(
                            'IndexedDB device-wrapping compare-and-swap',
                            error,
                        ),
                    );
                };
                transaction.addEventListener(
                    'complete',
                    () => {
                        if (
                            conflictDetected ||
                            operationFailure !== undefined
                        ) {
                            rejectTransaction(
                                operationFailure ??
                                    new IndexedDbUntrustedStorageAdapterError(
                                        'TransactionFailed',
                                        'IndexedDB committed device custody after an abort was requested.',
                                    ),
                            );
                            return;
                        }
                        resolve(true);
                    },
                    { once: true },
                );
                transaction.addEventListener(
                    'abort',
                    () => {
                        if (
                            conflictDetected &&
                            operationFailure === undefined
                        ) {
                            resolve(false);
                            return;
                        }
                        rejectTransaction(
                            operationFailure ?? transaction.error,
                        );
                    },
                    { once: true },
                );
                const noteRequestFailure = (request: IDBRequest): void => {
                    if (!conflictDetected) {
                        operationFailure ??= request.error;
                    }
                };
                const queueReplacement = (): void => {
                    try {
                        const request =
                            replacement === undefined
                                ? objectStore.delete(storageKey)
                                : objectStore.put(replacement, storageKey);
                        request.addEventListener('error', () => {
                            noteRequestFailure(request);
                        });
                    } catch (error) {
                        operationFailure = error;
                        this.#abortAfterOperationFailure(transaction, error);
                    }
                };
                let request: IDBRequest<IDBCursorWithValue | null>;
                try {
                    request = objectStore.openCursor(storageKey);
                } catch (error) {
                    operationFailure = error;
                    this.#abortAfterOperationFailure(transaction, error);
                    return;
                }
                request.addEventListener('success', () => {
                    try {
                        const cursor = request.result;
                        if (cursor !== null && cursor.key !== storageKey) {
                            throw new IndexedDbUntrustedStorageAdapterError(
                                'TransactionFailed',
                                'IndexedDB device-wrapping comparison returned a different key.',
                            );
                        }
                        const matches =
                            expectedMutationIdentifier === undefined
                                ? cursor === null
                                : cursor !== null &&
                                  bytesEqual(
                                      copyStoredDeviceWrappingRecord(
                                          cursor.value,
                                      ).mutationIdentifier,
                                      expectedMutationIdentifier,
                                  );
                        if (!matches) {
                            conflictDetected = true;
                            try {
                                transaction.abort();
                            } catch (error) {
                                conflictDetected = false;
                                operationFailure = error;
                            }
                            return;
                        }
                        queueReplacement();
                    } catch (error) {
                        operationFailure = error;
                        this.#abortAfterOperationFailure(transaction, error);
                    }
                });
                request.addEventListener('error', () => {
                    noteRequestFailure(request);
                });
            });
        });
    }

    async #verifySchema(): Promise<void> {
        if (
            this.#database.version !== databaseVersion ||
            this.#database.objectStoreNames.length !== 1 ||
            !this.#database.objectStoreNames.contains(objectStoreName)
        ) {
            throw new IndexedDbUntrustedStorageAdapterError(
                'SchemaMismatch',
                'IndexedDB database does not have the exact owned schema.',
            );
        }
        await this.#withOpenConnection(async (database) => {
            const transaction = this.#trackTransaction(
                database.transaction(objectStoreName, 'readonly'),
            );
            const objectStore = transaction.objectStore(objectStoreName);
            const completion = this.#waitForTransaction(
                transaction,
                'IndexedDB schema verification',
                () => undefined,
            );
            if (objectStore.keyPath !== null || objectStore.autoIncrement) {
                const schemaError = new IndexedDbUntrustedStorageAdapterError(
                    'SchemaMismatch',
                    'IndexedDB object store has unsupported key semantics.',
                );
                this.#abortAfterOperationFailure(transaction, schemaError);
                try {
                    await completion;
                } catch {
                    // The schema error below is the authoritative refusal.
                }
                throw schemaError;
            }
            await completion;
        });
    }

    async #verifyStrictDurability(): Promise<void> {
        await this.#withOpenConnection(async (database) => {
            const transaction = this.#strictReadwriteTransaction(database);
            await this.#waitForTransaction(
                transaction,
                'IndexedDB strict-durability probe',
                () => undefined,
            );
        });
    }

    #strictReadwriteTransaction(database: IDBDatabase): IDBTransaction {
        let transaction: IDBTransaction;
        try {
            transaction = database.transaction(objectStoreName, 'readwrite', {
                durability: 'strict',
            });
        } catch (error) {
            throw new IndexedDbUntrustedStorageAdapterError(
                'StrictDurabilityUnavailable',
                'IndexedDB strict-durability transactions are unavailable.',
                error,
            );
        }
        if (transaction.durability !== 'strict') {
            try {
                transaction.abort();
            } catch {
                // No mutation was queued, so the adapter can still fail closed.
            }
            throw new IndexedDbUntrustedStorageAdapterError(
                'StrictDurabilityUnavailable',
                'IndexedDB did not retain the requested strict durability.',
            );
        }

        return this.#trackTransaction(transaction);
    }

    async #withOpenConnection<Result>(
        operation: (database: IDBDatabase) => Promise<Result>,
    ): Promise<Result> {
        if (this.#connectionState !== 'open') {
            throw new IndexedDbUntrustedStorageAdapterError(
                'Closed',
                'IndexedDB storage adapter is closed.',
            );
        }
        this.#activeOperationCount += 1;
        try {
            return await operation(this.#database);
        } finally {
            this.#activeOperationCount -= 1;
            this.#finishCloseIfIdle();
        }
    }

    #waitForTransaction(
        transaction: IDBTransaction,
        operation: string,
        operationFailure: () => unknown,
    ): Promise<void> {
        return new Promise<void>((resolve, reject) => {
            transaction.addEventListener('complete', () => resolve(), {
                once: true,
            });
            transaction.addEventListener(
                'abort',
                () => {
                    reject(
                        this.#transactionFailure(
                            operation,
                            operationFailure() ?? transaction.error,
                        ),
                    );
                },
                { once: true },
            );
        });
    }

    #abortAfterOperationFailure(
        transaction: IDBTransaction,
        operationFailure: unknown,
    ): void {
        try {
            transaction.abort();
        } catch (abortError) {
            throw new IndexedDbUntrustedStorageAdapterError(
                'TransactionFailed',
                'IndexedDB operation and transaction abort both failed.',
                [operationFailure, abortError],
            );
        }
    }

    async #rejectAfterSynchronousRequestFailure(input: {
        completion: Promise<void>;
        operation: string;
        operationFailure: unknown;
        transaction: IDBTransaction;
    }): Promise<never> {
        let abortFailure: unknown;
        try {
            input.transaction.abort();
        } catch (error) {
            abortFailure = error;
        }
        try {
            await input.completion;
        } catch (transactionFailure) {
            if (abortFailure === undefined) {
                throw transactionFailure;
            }
            throw new IndexedDbUntrustedStorageAdapterError(
                'TransactionFailed',
                `${input.operation} request creation, transaction abort, and transaction completion failed.`,
                [input.operationFailure, abortFailure, transactionFailure],
            );
        }
        throw this.#transactionFailure(
            input.operation,
            abortFailure === undefined
                ? input.operationFailure
                : new IndexedDbUntrustedStorageAdapterError(
                      'TransactionFailed',
                      `${input.operation} request creation and transaction abort both failed.`,
                      [input.operationFailure, abortFailure],
                  ),
        );
    }

    #transactionFailure(operation: string, cause: unknown): Error {
        if (cause instanceof IndexedDbUntrustedStorageAdapterError) {
            return cause;
        }

        return new IndexedDbUntrustedStorageAdapterError(
            'TransactionFailed',
            `${operation} transaction aborted.`,
            cause,
        );
    }

    #trackTransaction(transaction: IDBTransaction): IDBTransaction {
        this.#activeTransactions.add(transaction);
        const forgetTransaction = (): void => {
            this.#activeTransactions.delete(transaction);
            this.#finishCloseIfIdle();
        };
        transaction.addEventListener('complete', forgetTransaction, {
            once: true,
        });
        transaction.addEventListener('abort', forgetTransaction, {
            once: true,
        });

        return transaction;
    }

    #beginForcedClose(databaseIsAlreadyClosed: boolean): void {
        if (this.#connectionState === 'closed') {
            return;
        }
        this.#connectionState = 'closing';
        if (databaseIsAlreadyClosed) {
            this.#databaseCloseRequested = true;
        }
        for (const transaction of this.#activeTransactions) {
            try {
                transaction.abort();
            } catch {
                // A transaction that finished before this event needs no abort.
            }
        }
        this.#requestDatabaseClose();
        this.#finishCloseIfIdle();
    }

    #requestDatabaseClose(): void {
        if (this.#databaseCloseRequested) {
            return;
        }
        this.#databaseCloseRequested = true;
        this.#database.close();
    }

    #finishCloseIfIdle(): void {
        if (
            this.#connectionState === 'closing' &&
            this.#activeOperationCount === 0 &&
            this.#activeTransactions.size === 0
        ) {
            this.#requestDatabaseClose();
            this.#markClosed();
        }
    }

    #markClosed(): void {
        if (this.#connectionState === 'closed') {
            return;
        }
        this.#connectionState = 'closed';
        this.#resolveClosedPromise();
    }
}

export const openIndexedDbUntrustedStorageAdapter = async (
    configuration: IndexedDbUntrustedStorageAdapterConfiguration,
): Promise<IndexedDbUntrustedStorageAdapter> =>
    IndexedDbUntrustedStorageAdapter.open(configuration);
