const databaseVersion = 4;
const rootStoreName = 'root';
const actionStoreName = 'actions';
const preparationStoreName = 'preparations';
const slotStoreName = 'slots';
const sourceStoreName = 'sources';
const finalityStoreName = 'finalities';
const activationStoreName = 'activations';
const evaluationStoreName = 'evaluations';
const rootRecordIdentifier = 'browser-local-hmac-root-v1';

type ProtectedStoreName =
    | typeof actionStoreName
    | typeof preparationStoreName
    | typeof slotStoreName
    | typeof sourceStoreName
    | typeof finalityStoreName
    | typeof activationStoreName
    | typeof evaluationStoreName;

const protectedStoreNames: readonly ProtectedStoreName[] = [
    actionStoreName,
    preparationStoreName,
    slotStoreName,
    sourceStoreName,
    finalityStoreName,
    activationStoreName,
    evaluationStoreName,
];

export type ProtectedRecord = Readonly<{
    id: string;
    context: ArrayBuffer;
    nonce: ArrayBuffer;
    ciphertext: ArrayBuffer;
}>;

type ProtectedRecordStorageMeasurement = Readonly<{
    storeName: ProtectedStoreName;
    recordCount: number;
    identifierUtf8ByteLength: number;
    authenticatedContextByteLength: number;
    nonceByteLength: number;
    ciphertextByteLength: number;
}>;

type RootRecord = Readonly<{
    id: typeof rootRecordIdentifier;
    key: CryptoKey;
    generation: bigint;
    inventoryAuthenticator: ArrayBuffer;
}>;

type StoredProtectedRecord = Readonly<{
    storeName: ProtectedStoreName;
    record: ProtectedRecord;
}>;

type DurableStateSnapshot = Readonly<{
    root: RootRecord | undefined;
    records: readonly StoredProtectedRecord[];
}>;

const rootInventoryAuthenticatorByteLength = 32;
const rootInventoryDomain = new TextEncoder().encode(
    'sealed-lattice.browser-local-inventory.v1',
);
const maximumInventoryGeneration = (1n << 32n) - 1n;

export class DurableStateError extends Error {
    constructor(
        readonly code:
            | 'Conflict'
            | 'CorruptState'
            | 'MissingPersistence'
            | 'StateLost'
            | 'StorageFailure',
        message: string,
    ) {
        super(message);
        this.name = 'DurableStateError';
    }
}

const requestResult = <Result>(request: IDBRequest<Result>): Promise<Result> =>
    new Promise((resolve, reject) => {
        request.addEventListener('success', () => {
            resolve(request.result);
        });
        request.addEventListener('error', () => {
            reject(
                new DurableStateError(
                    'StorageFailure',
                    'The durable-state request failed.',
                ),
            );
        });
    });

const unknownRequestResult = (request: IDBRequest): Promise<unknown> =>
    new Promise((resolve, reject) => {
        request.addEventListener('success', () => {
            const result: unknown = request.result;
            resolve(result);
        });
        request.addEventListener('error', () => {
            reject(
                new DurableStateError(
                    'StorageFailure',
                    'The durable-state request failed.',
                ),
            );
        });
    });

const transactionCompletion = (transaction: IDBTransaction): Promise<void> =>
    new Promise((resolve, reject) => {
        transaction.addEventListener('complete', () => {
            resolve();
        });
        transaction.addEventListener('abort', () => {
            reject(
                new DurableStateError(
                    'StorageFailure',
                    'The strict durable-state transaction was aborted.',
                ),
            );
        });
        transaction.addEventListener('error', () => {
            reject(
                new DurableStateError(
                    'StorageFailure',
                    'The strict durable-state transaction failed.',
                ),
            );
        });
    });

const openDatabase = (name: string): Promise<IDBDatabase> =>
    new Promise((resolve, reject) => {
        const request = indexedDB.open(name, databaseVersion);
        request.addEventListener('upgradeneeded', () => {
            const database = request.result;
            for (const storeName of [rootStoreName, ...protectedStoreNames]) {
                if (!database.objectStoreNames.contains(storeName)) {
                    database.createObjectStore(storeName, { keyPath: 'id' });
                }
            }
        });
        request.addEventListener('success', () => {
            resolve(request.result);
        });
        request.addEventListener('blocked', () => {
            reject(
                new DurableStateError(
                    'StorageFailure',
                    'The durable-state database upgrade is blocked.',
                ),
            );
        });
        request.addEventListener('error', () => {
            reject(
                new DurableStateError(
                    'StorageFailure',
                    'The durable-state database could not be opened.',
                ),
            );
        });
    });

const copyArrayBuffer = (value: ArrayBuffer): ArrayBuffer => value.slice(0);

const isArrayBuffer = (value: unknown): value is ArrayBuffer =>
    value instanceof ArrayBuffer;

const bytesEqual = (left: ArrayBuffer, right: ArrayBuffer): boolean => {
    const leftBytes = new Uint8Array(left);
    const rightBytes = new Uint8Array(right);
    if (leftBytes.byteLength !== rightBytes.byteLength) {
        return false;
    }
    let difference = 0;
    for (let index = 0; index < leftBytes.byteLength; index += 1) {
        difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
    }
    return difference === 0;
};

const isProtectedRecord = (value: unknown): value is ProtectedRecord => {
    if (typeof value !== 'object' || value === null) {
        return false;
    }
    const candidate = value as Partial<ProtectedRecord>;
    return (
        typeof candidate.id === 'string' &&
        isArrayBuffer(candidate.context) &&
        isArrayBuffer(candidate.nonce) &&
        isArrayBuffer(candidate.ciphertext)
    );
};

const protectedRecordsEqual = (
    left: ProtectedRecord,
    right: ProtectedRecord,
): boolean =>
    left.id === right.id &&
    bytesEqual(left.context, right.context) &&
    bytesEqual(left.nonce, right.nonce) &&
    bytesEqual(left.ciphertext, right.ciphertext);

const cloneProtectedRecord = (record: ProtectedRecord): ProtectedRecord => ({
    id: record.id,
    context: copyArrayBuffer(record.context),
    nonce: copyArrayBuffer(record.nonce),
    ciphertext: copyArrayBuffer(record.ciphertext),
});

const cloneRootRecord = (record: RootRecord): RootRecord => ({
    id: rootRecordIdentifier,
    key: record.key,
    generation: record.generation,
    inventoryAuthenticator: copyArrayBuffer(record.inventoryAuthenticator),
});

const validateRootKey = (value: unknown): CryptoKey => {
    if (!(value instanceof CryptoKey)) {
        throw new DurableStateError(
            'CorruptState',
            'The browser-local root capability is malformed.',
        );
    }
    const algorithm = value.algorithm;
    if (
        algorithm.name !== 'HMAC' ||
        value.extractable ||
        value.usages.length !== 1 ||
        value.usages[0] !== 'sign'
    ) {
        throw new DurableStateError(
            'CorruptState',
            'The browser-local root capability has the wrong algorithm or usage.',
        );
    }
    return value;
};

const validateRootRecord = (value: unknown): RootRecord => {
    if (typeof value !== 'object' || value === null) {
        throw new DurableStateError(
            'CorruptState',
            'The browser-local root record is malformed.',
        );
    }
    const candidate = value as Partial<RootRecord>;
    if (
        candidate.id !== rootRecordIdentifier ||
        typeof candidate.generation !== 'bigint' ||
        candidate.generation < 1n ||
        candidate.generation > maximumInventoryGeneration ||
        !isArrayBuffer(candidate.inventoryAuthenticator) ||
        candidate.inventoryAuthenticator.byteLength !==
            rootInventoryAuthenticatorByteLength
    ) {
        throw new DurableStateError(
            'CorruptState',
            'The browser-local root record has invalid identity or inventory fields.',
        );
    }
    return {
        id: rootRecordIdentifier,
        key: validateRootKey(candidate.key),
        generation: candidate.generation,
        inventoryAuthenticator: copyArrayBuffer(
            candidate.inventoryAuthenticator,
        ),
    };
};

const compareStoredProtectedRecords = (
    left: StoredProtectedRecord,
    right: StoredProtectedRecord,
): number => {
    const storeOrder =
        protectedStoreNames.indexOf(left.storeName) -
        protectedStoreNames.indexOf(right.storeName);
    if (storeOrder !== 0) {
        return storeOrder;
    }
    return left.record.id < right.record.id
        ? -1
        : left.record.id > right.record.id
          ? 1
          : 0;
};

const normalizeStoredProtectedRecords = (
    records: readonly StoredProtectedRecord[],
): StoredProtectedRecord[] =>
    records
        .map(({ storeName, record }) => ({
            storeName,
            record: cloneProtectedRecord(record),
        }))
        .sort(compareStoredProtectedRecords);

const storedProtectedRecordSetsEqual = (
    left: readonly StoredProtectedRecord[],
    right: readonly StoredProtectedRecord[],
): boolean =>
    left.length === right.length &&
    left.every((entry, index) => {
        const other = right[index];
        return (
            other !== undefined &&
            entry.storeName === other.storeName &&
            protectedRecordsEqual(entry.record, other.record)
        );
    });

const checkedUnsigned32 = (value: number, name: string): number => {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw new DurableStateError(
            'CorruptState',
            `The browser-local ${name} exceeds its canonical bound.`,
        );
    }
    return value;
};

const encodeInventoryAuthenticatorInput = (
    generation: bigint,
    records: readonly StoredProtectedRecord[],
): Uint8Array<ArrayBuffer> => {
    if (generation < 1n || generation > maximumInventoryGeneration) {
        throw new DurableStateError(
            'CorruptState',
            'The browser-local inventory generation is invalid.',
        );
    }
    const normalized = normalizeStoredProtectedRecords(records);
    const textEncoder = new TextEncoder();
    const encodedIdentifiers = normalized.map(({ record }) =>
        textEncoder.encode(record.id),
    );
    let byteLength = rootInventoryDomain.byteLength + 8 + 4;
    for (let index = 0; index < normalized.length; index += 1) {
        const entry = normalized[index];
        const encodedIdentifier = encodedIdentifiers[index];
        if (entry === undefined || encodedIdentifier === undefined) {
            throw new DurableStateError(
                'CorruptState',
                'The browser-local inventory is inconsistent.',
            );
        }
        checkedUnsigned32(encodedIdentifier.byteLength, 'record identity');
        checkedUnsigned32(entry.record.context.byteLength, 'record context');
        checkedUnsigned32(entry.record.nonce.byteLength, 'record nonce');
        checkedUnsigned32(
            entry.record.ciphertext.byteLength,
            'record ciphertext',
        );
        byteLength +=
            1 +
            4 +
            encodedIdentifier.byteLength +
            4 +
            entry.record.context.byteLength +
            4 +
            entry.record.nonce.byteLength +
            4 +
            entry.record.ciphertext.byteLength;
        if (!Number.isSafeInteger(byteLength)) {
            throw new DurableStateError(
                'CorruptState',
                'The browser-local inventory is too large to authenticate.',
            );
        }
    }
    checkedUnsigned32(normalized.length, 'record count');
    const bytes = new Uint8Array(new ArrayBuffer(byteLength));
    const view = new DataView(bytes.buffer);
    let offset = 0;
    bytes.set(rootInventoryDomain, offset);
    offset += rootInventoryDomain.byteLength;
    view.setBigUint64(offset, generation, true);
    offset += 8;
    view.setUint32(offset, normalized.length, true);
    offset += 4;
    for (let index = 0; index < normalized.length; index += 1) {
        const entry = normalized[index];
        const encodedIdentifier = encodedIdentifiers[index];
        if (entry === undefined || encodedIdentifier === undefined) {
            throw new DurableStateError(
                'CorruptState',
                'The browser-local inventory changed during encoding.',
            );
        }
        const storeOrdinal = protectedStoreNames.indexOf(entry.storeName);
        if (storeOrdinal < 0) {
            throw new DurableStateError(
                'CorruptState',
                'The browser-local inventory names an unknown store.',
            );
        }
        bytes[offset] = storeOrdinal;
        offset += 1;
        view.setUint32(offset, encodedIdentifier.byteLength, true);
        offset += 4;
        bytes.set(encodedIdentifier, offset);
        offset += encodedIdentifier.byteLength;
        for (const field of [
            entry.record.context,
            entry.record.nonce,
            entry.record.ciphertext,
        ]) {
            view.setUint32(offset, field.byteLength, true);
            offset += 4;
            bytes.set(new Uint8Array(field), offset);
            offset += field.byteLength;
        }
    }
    if (offset !== bytes.byteLength) {
        throw new DurableStateError(
            'CorruptState',
            'The browser-local inventory encoding is inconsistent.',
        );
    }
    return bytes;
};

const authenticateInventory = async (
    rootKey: CryptoKey,
    generation: bigint,
    records: readonly StoredProtectedRecord[],
): Promise<ArrayBuffer> => {
    validateRootKey(rootKey);
    const input = encodeInventoryAuthenticatorInput(generation, records);
    try {
        return await crypto.subtle.sign('HMAC', rootKey, input.buffer);
    } finally {
        input.fill(0);
    }
};

const rootRecordMetadataEqual = (
    left: RootRecord,
    right: RootRecord,
): boolean =>
    left.generation === right.generation &&
    bytesEqual(left.inventoryAuthenticator, right.inventoryAuthenticator);

const requirePersistentStorage = async (): Promise<void> => {
    const storage = navigator.storage;
    if (
        storage === undefined ||
        typeof storage.persist !== 'function' ||
        typeof storage.persisted !== 'function'
    ) {
        throw new DurableStateError(
            'MissingPersistence',
            'Persistent browser storage is unavailable.',
        );
    }
    if (!(await storage.persisted()) && !(await storage.persist())) {
        throw new DurableStateError(
            'MissingPersistence',
            'Persistent browser storage was not granted.',
        );
    }
};

export const generateBrowserLocalRootKey = (): Promise<CryptoKey> =>
    crypto.subtle.generateKey(
        { name: 'HMAC', hash: 'SHA-256', length: 256 },
        false,
        ['sign'],
    );

export class PrivatePreparationDurableState {
    readonly #database: IDBDatabase;
    readonly #lockName: string;

    private constructor(database: IDBDatabase, databaseName: string) {
        this.#database = database;
        this.#lockName = `sealed-lattice-private-preparation:${databaseName}`;
    }

    static async open(
        databaseName: string,
        persistentStorageRequired: boolean,
    ): Promise<PrivatePreparationDurableState> {
        if (
            databaseName.length < 1 ||
            databaseName.length > 128 ||
            !/^[A-Za-z0-9._-]+$/u.test(databaseName)
        ) {
            throw new TypeError('The durable-state database name is invalid.');
        }
        if (persistentStorageRequired) {
            await requirePersistentStorage();
        }
        return new PrivatePreparationDurableState(
            await openDatabase(databaseName),
            databaseName,
        );
    }

    close(): void {
        this.#database.close();
    }

    async exclusive<Result>(operation: () => Promise<Result>): Promise<Result> {
        const lockManager = navigator.locks;
        if (lockManager === undefined) {
            throw new DurableStateError(
                'StorageFailure',
                'Exclusive browser storage mutation is unavailable.',
            );
        }
        return lockManager.request(
            this.#lockName,
            { mode: 'exclusive' },
            operation,
        );
    }

    async #readVerifiedSnapshot(): Promise<DurableStateSnapshot> {
        const transaction = this.#database.transaction(
            [rootStoreName, ...protectedStoreNames],
            'readonly',
        );
        const [unknownRoots, ...unknownStoreRecords] = await Promise.all([
            unknownRequestResult(
                transaction.objectStore(rootStoreName).getAll(),
            ),
            ...protectedStoreNames.map((storeName) =>
                unknownRequestResult(
                    transaction.objectStore(storeName).getAll(),
                ),
            ),
        ]);
        await transactionCompletion(transaction);
        if (!Array.isArray(unknownRoots)) {
            throw new DurableStateError(
                'CorruptState',
                'The browser-local root store is malformed.',
            );
        }
        const records: StoredProtectedRecord[] = [];
        for (
            let storeIndex = 0;
            storeIndex < protectedStoreNames.length;
            storeIndex += 1
        ) {
            const storeName = protectedStoreNames[storeIndex];
            const unknownRecords = unknownStoreRecords[storeIndex];
            if (storeName === undefined || !Array.isArray(unknownRecords)) {
                throw new DurableStateError(
                    'CorruptState',
                    'A protected browser-local store is malformed.',
                );
            }
            for (const value of unknownRecords) {
                if (!isProtectedRecord(value)) {
                    throw new DurableStateError(
                        'CorruptState',
                        'A protected browser-local record is malformed.',
                    );
                }
                records.push({
                    storeName,
                    record: cloneProtectedRecord(value),
                });
            }
        }
        const normalizedRecords = normalizeStoredProtectedRecords(records);
        if (unknownRoots.length === 0) {
            if (normalizedRecords.length !== 0) {
                throw new DurableStateError(
                    'StateLost',
                    'The browser-local root is absent while protected state remains.',
                );
            }
            return { root: undefined, records: normalizedRecords };
        }
        if (unknownRoots.length !== 1) {
            throw new DurableStateError(
                'CorruptState',
                'The browser-local root store has an invalid inventory.',
            );
        }
        const root = validateRootRecord(unknownRoots[0]);
        const computedAuthenticator = await authenticateInventory(
            root.key,
            root.generation,
            normalizedRecords,
        );
        if (!bytesEqual(root.inventoryAuthenticator, computedAuthenticator)) {
            throw new DurableStateError(
                'StateLost',
                'The protected browser-local inventory does not match its root capability.',
            );
        }
        return { root, records: normalizedRecords };
    }

    async #commitReboundInventory(
        previous: DurableStateSnapshot,
        desiredRecords: readonly StoredProtectedRecord[],
    ): Promise<void> {
        if (previous.root === undefined) {
            throw new DurableStateError(
                'StateLost',
                'The browser-local root is absent for a durable transition.',
            );
        }
        if (previous.root.generation === maximumInventoryGeneration) {
            throw new DurableStateError(
                'StateLost',
                'The browser-local inventory generation is exhausted.',
            );
        }
        const normalizedDesiredRecords =
            normalizeStoredProtectedRecords(desiredRecords);
        const nextGeneration = previous.root.generation + 1n;
        const resealedRecords: StoredProtectedRecord[] = [];
        for (const { storeName, record } of normalizedDesiredRecords) {
            const context = new Uint8Array(record.context);
            let plaintext: Uint8Array | undefined;
            try {
                plaintext = await openProtectedRecord(
                    record,
                    context,
                    previous.root.key,
                );
                resealedRecords.push({
                    storeName,
                    record: await createInventoryProtectedRecord(
                        record.id,
                        context,
                        plaintext,
                        previous.root.key,
                        nextGeneration,
                    ),
                });
            } finally {
                context.fill(0);
                plaintext?.fill(0);
            }
        }
        const nextRoot: RootRecord = {
            id: rootRecordIdentifier,
            key: previous.root.key,
            generation: nextGeneration,
            inventoryAuthenticator: await authenticateInventory(
                previous.root.key,
                nextGeneration,
                resealedRecords,
            ),
        };
        const transaction = this.#database.transaction(
            [rootStoreName, ...protectedStoreNames],
            'readwrite',
            { durability: 'strict' },
        );
        const completion = transactionCompletion(transaction);
        const [unknownRoots, ...unknownStoreRecords] = await Promise.all([
            unknownRequestResult(
                transaction.objectStore(rootStoreName).getAll(),
            ),
            ...protectedStoreNames.map((storeName) =>
                unknownRequestResult(
                    transaction.objectStore(storeName).getAll(),
                ),
            ),
        ]);
        let currentRoot: RootRecord | undefined;
        const currentRecords: StoredProtectedRecord[] = [];
        try {
            if (!Array.isArray(unknownRoots) || unknownRoots.length !== 1) {
                throw new DurableStateError(
                    'Conflict',
                    'The browser-local root changed before commit.',
                );
            }
            currentRoot = validateRootRecord(unknownRoots[0]);
            for (
                let storeIndex = 0;
                storeIndex < protectedStoreNames.length;
                storeIndex += 1
            ) {
                const storeName = protectedStoreNames[storeIndex];
                const unknownRecords = unknownStoreRecords[storeIndex];
                if (storeName === undefined || !Array.isArray(unknownRecords)) {
                    throw new DurableStateError(
                        'Conflict',
                        'A protected browser-local store changed before commit.',
                    );
                }
                for (const value of unknownRecords) {
                    if (!isProtectedRecord(value)) {
                        throw new DurableStateError(
                            'Conflict',
                            'A protected browser-local record changed before commit.',
                        );
                    }
                    currentRecords.push({
                        storeName,
                        record: cloneProtectedRecord(value),
                    });
                }
            }
        } catch (error) {
            transaction.abort();
            await completion.catch(() => undefined);
            throw error;
        }
        if (
            currentRoot === undefined ||
            !rootRecordMetadataEqual(currentRoot, previous.root) ||
            !storedProtectedRecordSetsEqual(
                normalizeStoredProtectedRecords(currentRecords),
                previous.records,
            )
        ) {
            transaction.abort();
            await completion.catch(() => undefined);
            throw new DurableStateError(
                'Conflict',
                'The complete durable predecessor changed before commit.',
            );
        }
        transaction.objectStore(rootStoreName).clear();
        for (const storeName of protectedStoreNames) {
            transaction.objectStore(storeName).clear();
        }
        transaction.objectStore(rootStoreName).put(cloneRootRecord(nextRoot));
        for (const { storeName, record } of resealedRecords) {
            transaction
                .objectStore(storeName)
                .put(cloneProtectedRecord(record));
        }
        await completion;
    }

    async readRoot(): Promise<CryptoKey | undefined> {
        return (await this.#readVerifiedSnapshot()).root?.key;
    }

    async readProtected(
        storeName: ProtectedStoreName,
        identifier: string,
    ): Promise<ProtectedRecord | undefined> {
        const snapshot = await this.#readVerifiedSnapshot();
        return snapshot.records.find(
            (entry) =>
                entry.storeName === storeName && entry.record.id === identifier,
        )?.record;
    }

    async countProtectedRecords(): Promise<number> {
        return (await this.#readVerifiedSnapshot()).records.length;
    }

    async measureProtectedRecords(): Promise<
        readonly ProtectedRecordStorageMeasurement[]
    > {
        const snapshot = await this.#readVerifiedSnapshot();
        const textEncoder = new TextEncoder();
        return protectedStoreNames.map((storeName) => {
            const records = snapshot.records
                .filter((entry) => entry.storeName === storeName)
                .map((entry) => entry.record);
            return {
                storeName,
                recordCount: records.length,
                identifierUtf8ByteLength: records.reduce(
                    (sum, record) =>
                        sum + textEncoder.encode(record.id).byteLength,
                    0,
                ),
                authenticatedContextByteLength: records.reduce(
                    (sum, record) => sum + record.context.byteLength,
                    0,
                ),
                nonceByteLength: records.reduce(
                    (sum, record) => sum + record.nonce.byteLength,
                    0,
                ),
                ciphertextByteLength: records.reduce(
                    (sum, record) => sum + record.ciphertext.byteLength,
                    0,
                ),
            };
        });
    }

    async initializeRootAndAction(
        rootKey: CryptoKey,
        action: ProtectedRecord,
    ): Promise<void> {
        validateRootKey(rootKey);
        const generation = 1n;
        const actionContext = new Uint8Array(action.context);
        let actionPlaintext: Uint8Array | undefined;
        let retainedAction: ProtectedRecord;
        try {
            actionPlaintext = await openProtectedRecord(
                action,
                actionContext,
                rootKey,
            );
            retainedAction = await createInventoryProtectedRecord(
                action.id,
                actionContext,
                actionPlaintext,
                rootKey,
                generation,
            );
        } finally {
            actionContext.fill(0);
            actionPlaintext?.fill(0);
        }
        const records = normalizeStoredProtectedRecords([
            { storeName: actionStoreName, record: retainedAction },
        ]);
        const root: RootRecord = {
            id: rootRecordIdentifier,
            key: rootKey,
            generation,
            inventoryAuthenticator: await authenticateInventory(
                rootKey,
                generation,
                records,
            ),
        };
        const transaction = this.#database.transaction(
            [rootStoreName, ...protectedStoreNames],
            'readwrite',
            { durability: 'strict' },
        );
        const completion = transactionCompletion(transaction);
        const rootStore = transaction.objectStore(rootStoreName);
        const actionStore = transaction.objectStore(actionStoreName);
        const rootCount = await requestResult<number>(rootStore.count());
        const existingAction = await unknownRequestResult(
            actionStore.get(action.id),
        );
        const stateCounts = await Promise.all(
            protectedStoreNames.map((storeName) =>
                requestResult<number>(
                    transaction.objectStore(storeName).count(),
                ),
            ),
        );
        if (
            rootCount !== 0 ||
            existingAction !== undefined ||
            stateCounts.some((count) => count !== 0)
        ) {
            transaction.abort();
            await completion.catch(() => undefined);
            throw new DurableStateError(
                'Conflict',
                'Durable action state appeared during initialization.',
            );
        }
        rootStore.put(cloneRootRecord(root));
        actionStore.put(cloneProtectedRecord(retainedAction));
        await completion;
    }

    async putIfAbsent(
        storeName: ProtectedStoreName,
        record: ProtectedRecord,
    ): Promise<void> {
        const snapshot = await this.#readVerifiedSnapshot();
        if (
            snapshot.records.some(
                (entry) =>
                    entry.storeName === storeName &&
                    entry.record.id === record.id,
            )
        ) {
            throw new DurableStateError(
                'Conflict',
                'The durable semantic slot is already occupied.',
            );
        }
        await this.#commitReboundInventory(snapshot, [
            ...snapshot.records,
            { storeName, record },
        ]);
    }

    async replaceExact(
        storeName: ProtectedStoreName,
        expected: ProtectedRecord,
        replacement: ProtectedRecord,
    ): Promise<void> {
        if (expected.id !== replacement.id) {
            throw new DurableStateError(
                'Conflict',
                'A durable replacement changed its stable identity.',
            );
        }
        const snapshot = await this.#readVerifiedSnapshot();
        const recordIndex = snapshot.records.findIndex(
            (entry) =>
                entry.storeName === storeName &&
                entry.record.id === expected.id,
        );
        const existing = snapshot.records[recordIndex];
        if (
            existing === undefined ||
            !protectedRecordsEqual(existing.record, expected)
        ) {
            throw new DurableStateError(
                'Conflict',
                'The durable predecessor changed before replacement.',
            );
        }
        const desiredRecords = [...snapshot.records];
        desiredRecords[recordIndex] = { storeName, record: replacement };
        await this.#commitReboundInventory(snapshot, desiredRecords);
    }

    async replaceExactAndPutIfAbsent(
        replacementStoreName: ProtectedStoreName,
        expected: ProtectedRecord,
        replacement: ProtectedRecord,
        insertionStoreName: ProtectedStoreName,
        insertion: ProtectedRecord,
    ): Promise<void> {
        if (
            expected.id !== replacement.id ||
            (replacementStoreName === insertionStoreName &&
                replacement.id === insertion.id)
        ) {
            throw new DurableStateError(
                'Conflict',
                'The atomic durable transition has conflicting identities.',
            );
        }
        const snapshot = await this.#readVerifiedSnapshot();
        const replacementIndex = snapshot.records.findIndex(
            (entry) =>
                entry.storeName === replacementStoreName &&
                entry.record.id === expected.id,
        );
        const existingReplacement = snapshot.records[replacementIndex];
        const existingInsertion = snapshot.records.find(
            (entry) =>
                entry.storeName === insertionStoreName &&
                entry.record.id === insertion.id,
        );
        if (
            existingReplacement === undefined ||
            !protectedRecordsEqual(existingReplacement.record, expected) ||
            existingInsertion !== undefined
        ) {
            throw new DurableStateError(
                'Conflict',
                'The atomic durable predecessor changed or its destination is occupied.',
            );
        }
        const desiredRecords = [...snapshot.records];
        desiredRecords[replacementIndex] = {
            storeName: replacementStoreName,
            record: replacement,
        };
        desiredRecords.push({
            storeName: insertionStoreName,
            record: insertion,
        });
        await this.#commitReboundInventory(snapshot, desiredRecords);
    }

    async replaceTwoExact(
        firstStoreName: ProtectedStoreName,
        firstExpected: ProtectedRecord,
        firstReplacement: ProtectedRecord,
        secondStoreName: ProtectedStoreName,
        secondExpected: ProtectedRecord,
        secondReplacement: ProtectedRecord,
    ): Promise<void> {
        if (
            firstExpected.id !== firstReplacement.id ||
            secondExpected.id !== secondReplacement.id ||
            (firstStoreName === secondStoreName &&
                firstExpected.id === secondExpected.id)
        ) {
            throw new DurableStateError(
                'Conflict',
                'The atomic durable replacements have conflicting identities.',
            );
        }
        const snapshot = await this.#readVerifiedSnapshot();
        const firstIndex = snapshot.records.findIndex(
            (entry) =>
                entry.storeName === firstStoreName &&
                entry.record.id === firstExpected.id,
        );
        const secondIndex = snapshot.records.findIndex(
            (entry) =>
                entry.storeName === secondStoreName &&
                entry.record.id === secondExpected.id,
        );
        const existingFirst = snapshot.records[firstIndex];
        const existingSecond = snapshot.records[secondIndex];
        if (
            existingFirst === undefined ||
            !protectedRecordsEqual(existingFirst.record, firstExpected) ||
            existingSecond === undefined ||
            !protectedRecordsEqual(existingSecond.record, secondExpected)
        ) {
            throw new DurableStateError(
                'Conflict',
                'An atomic durable predecessor changed before replacement.',
            );
        }
        const desiredRecords = [...snapshot.records];
        desiredRecords[firstIndex] = {
            storeName: firstStoreName,
            record: firstReplacement,
        };
        desiredRecords[secondIndex] = {
            storeName: secondStoreName,
            record: secondReplacement,
        };
        await this.#commitReboundInventory(snapshot, desiredRecords);
    }
}

const sealProtectedRecord = async (
    identifier: string,
    context: Uint8Array,
    plaintext: Uint8Array,
    rootKey: CryptoKey,
    nonce: Uint8Array<ArrayBuffer>,
): Promise<ProtectedRecord> => {
    validateRootKey(rootKey);
    if (
        context.byteLength === 0 ||
        plaintext.byteLength === 0 ||
        nonce.byteLength !== 12
    ) {
        throw new TypeError('Protected record inputs must be nonempty.');
    }
    const keyInput = new Uint8Array(context.byteLength + 1);
    keyInput.set(context);
    keyInput[keyInput.byteLength - 1] = 1;
    const derivedKeyBytes = new Uint8Array(
        await crypto.subtle.sign('HMAC', rootKey, keyInput),
    );
    keyInput.fill(0);
    let encryptionKey: CryptoKey;
    try {
        encryptionKey = await crypto.subtle.importKey(
            'raw',
            derivedKeyBytes,
            'AES-GCM',
            false,
            ['encrypt'],
        );
    } finally {
        derivedKeyBytes.fill(0);
    }
    const plaintextCopy = Uint8Array.from(plaintext);
    const digest = new Uint8Array(
        await crypto.subtle.digest('SHA-256', plaintextCopy.buffer),
    );
    const envelope = new Uint8Array(
        4 + digest.byteLength + plaintext.byteLength,
    );
    new DataView(envelope.buffer).setUint32(0, plaintext.byteLength, true);
    envelope.set(digest, 4);
    envelope.set(plaintextCopy, 4 + digest.byteLength);
    digest.fill(0);
    plaintextCopy.fill(0);
    try {
        const ciphertext = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: nonce,
                additionalData: Uint8Array.from(context).buffer,
                tagLength: 128,
            },
            encryptionKey,
            envelope,
        );
        return {
            id: identifier,
            context: Uint8Array.from(context).buffer,
            nonce: Uint8Array.from(nonce).buffer,
            ciphertext,
        };
    } finally {
        envelope.fill(0);
        nonce.fill(0);
    }
};

export const createProtectedRecord = (
    identifier: string,
    context: Uint8Array,
    plaintext: Uint8Array,
    rootKey: CryptoKey,
): Promise<ProtectedRecord> =>
    sealProtectedRecord(
        identifier,
        context,
        plaintext,
        rootKey,
        crypto.getRandomValues(new Uint8Array(12)),
    );

const createInventoryProtectedRecord = async (
    identifier: string,
    context: Uint8Array,
    plaintext: Uint8Array,
    rootKey: CryptoKey,
    inventoryGeneration: bigint,
): Promise<ProtectedRecord> => {
    if (
        inventoryGeneration < 1n ||
        inventoryGeneration > maximumInventoryGeneration
    ) {
        throw new DurableStateError(
            'CorruptState',
            'The protected-record inventory generation is invalid.',
        );
    }
    const nonceInput = new Uint8Array(context.byteLength + 1);
    nonceInput.set(context);
    nonceInput[nonceInput.byteLength - 1] = 2;
    const noncePrefix = new Uint8Array(
        await crypto.subtle.sign('HMAC', rootKey, nonceInput),
    );
    nonceInput.fill(0);
    const nonce = new Uint8Array(12);
    nonce.set(noncePrefix.subarray(0, 8));
    new DataView(nonce.buffer).setUint32(8, Number(inventoryGeneration), true);
    noncePrefix.fill(0);
    return sealProtectedRecord(identifier, context, plaintext, rootKey, nonce);
};

export const openProtectedRecord = async (
    record: ProtectedRecord,
    expectedContext: Uint8Array,
    rootKey: CryptoKey,
): Promise<Uint8Array> => {
    validateRootKey(rootKey);
    if (!bytesEqual(record.context, Uint8Array.from(expectedContext).buffer)) {
        throw new DurableStateError(
            'CorruptState',
            'The protected record context does not match local state.',
        );
    }
    const keyInput = new Uint8Array(expectedContext.byteLength + 1);
    keyInput.set(expectedContext);
    keyInput[keyInput.byteLength - 1] = 1;
    const derivedKeyBytes = new Uint8Array(
        await crypto.subtle.sign('HMAC', rootKey, keyInput),
    );
    keyInput.fill(0);
    let decryptionKey: CryptoKey;
    try {
        decryptionKey = await crypto.subtle.importKey(
            'raw',
            derivedKeyBytes,
            'AES-GCM',
            false,
            ['decrypt'],
        );
    } finally {
        derivedKeyBytes.fill(0);
    }
    let envelope: Uint8Array;
    try {
        envelope = new Uint8Array(
            await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: record.nonce,
                    additionalData: Uint8Array.from(expectedContext).buffer,
                    tagLength: 128,
                },
                decryptionKey,
                record.ciphertext,
            ),
        );
    } catch {
        throw new DurableStateError(
            'CorruptState',
            'The protected record failed authentication.',
        );
    }
    try {
        if (envelope.byteLength < 36) {
            throw new DurableStateError(
                'CorruptState',
                'The protected record plaintext is truncated.',
            );
        }
        const plaintextLength = new DataView(
            envelope.buffer,
            envelope.byteOffset,
            4,
        ).getUint32(0, true);
        if (plaintextLength !== envelope.byteLength - 36) {
            throw new DurableStateError(
                'CorruptState',
                'The protected record plaintext length is inconsistent.',
            );
        }
        const plaintext = Uint8Array.from(envelope.subarray(36));
        const expectedDigest = new Uint8Array(
            await crypto.subtle.digest('SHA-256', plaintext.buffer),
        );
        let difference = 0;
        for (let index = 0; index < expectedDigest.byteLength; index += 1) {
            difference |=
                (expectedDigest[index] ?? 0) ^ (envelope[4 + index] ?? 0);
        }
        expectedDigest.fill(0);
        if (difference !== 0) {
            plaintext.fill(0);
            throw new DurableStateError(
                'CorruptState',
                'The protected record plaintext digest is inconsistent.',
            );
        }
        return plaintext;
    } finally {
        envelope.fill(0);
    }
};
