const databaseVersion = 2;
const rootStoreName = 'root';
const actionStoreName = 'actions';
const preparationStoreName = 'preparations';
const slotStoreName = 'slots';
const sourceStoreName = 'sources';
const rootRecordIdentifier = 'browser-local-hmac-root-v1';

type ProtectedStoreName =
    | typeof actionStoreName
    | typeof preparationStoreName
    | typeof slotStoreName
    | typeof sourceStoreName;

export type ProtectedRecord = Readonly<{
    id: string;
    context: ArrayBuffer;
    nonce: ArrayBuffer;
    ciphertext: ArrayBuffer;
}>;

type RootRecord = Readonly<{
    id: typeof rootRecordIdentifier;
    key: CryptoKey;
}>;

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
            for (const storeName of [
                rootStoreName,
                actionStoreName,
                preparationStoreName,
                slotStoreName,
                sourceStoreName,
            ]) {
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
    if (candidate.id !== rootRecordIdentifier) {
        throw new DurableStateError(
            'CorruptState',
            'The browser-local root record has the wrong identity.',
        );
    }
    return { id: rootRecordIdentifier, key: validateRootKey(candidate.key) };
};

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

    async readRoot(): Promise<CryptoKey | undefined> {
        const transaction = this.#database.transaction(
            rootStoreName,
            'readonly',
        );
        const value = await unknownRequestResult(
            transaction.objectStore(rootStoreName).get(rootRecordIdentifier),
        );
        await transactionCompletion(transaction);
        return value === undefined ? undefined : validateRootRecord(value).key;
    }

    async readProtected(
        storeName: ProtectedStoreName,
        identifier: string,
    ): Promise<ProtectedRecord | undefined> {
        const transaction = this.#database.transaction(storeName, 'readonly');
        const value = await unknownRequestResult(
            transaction.objectStore(storeName).get(identifier),
        );
        await transactionCompletion(transaction);
        if (value === undefined) {
            return undefined;
        }
        if (!isProtectedRecord(value)) {
            throw new DurableStateError(
                'CorruptState',
                'A protected browser-local record is malformed.',
            );
        }
        return cloneProtectedRecord(value);
    }

    async countProtectedRecords(): Promise<number> {
        const transaction = this.#database.transaction(
            [
                actionStoreName,
                preparationStoreName,
                slotStoreName,
                sourceStoreName,
            ],
            'readonly',
        );
        const counts = await Promise.all(
            [
                actionStoreName,
                preparationStoreName,
                slotStoreName,
                sourceStoreName,
            ].map((storeName) =>
                requestResult<number>(
                    transaction.objectStore(storeName).count(),
                ),
            ),
        );
        await transactionCompletion(transaction);
        return counts.reduce((sum, count) => sum + count, 0);
    }

    async initializeRootAndAction(
        rootKey: CryptoKey,
        action: ProtectedRecord,
    ): Promise<void> {
        validateRootKey(rootKey);
        const transaction = this.#database.transaction(
            [
                rootStoreName,
                actionStoreName,
                preparationStoreName,
                slotStoreName,
                sourceStoreName,
            ],
            'readwrite',
            { durability: 'strict' },
        );
        const completion = transactionCompletion(transaction);
        const rootStore = transaction.objectStore(rootStoreName);
        const actionStore = transaction.objectStore(actionStoreName);
        const existingRoot = await unknownRequestResult(
            rootStore.get(rootRecordIdentifier),
        );
        const existingAction = await unknownRequestResult(
            actionStore.get(action.id),
        );
        const stateCounts = await Promise.all(
            [
                actionStoreName,
                preparationStoreName,
                slotStoreName,
                sourceStoreName,
            ].map((storeName) =>
                requestResult<number>(
                    transaction.objectStore(storeName).count(),
                ),
            ),
        );
        if (
            existingRoot !== undefined ||
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
        rootStore.put({ id: rootRecordIdentifier, key: rootKey });
        actionStore.put(cloneProtectedRecord(action));
        await completion;
    }

    async putIfAbsent(
        storeName: ProtectedStoreName,
        record: ProtectedRecord,
    ): Promise<void> {
        const transaction = this.#database.transaction(storeName, 'readwrite', {
            durability: 'strict',
        });
        const completion = transactionCompletion(transaction);
        const store = transaction.objectStore(storeName);
        const existing = await unknownRequestResult(store.get(record.id));
        if (existing !== undefined) {
            transaction.abort();
            await completion.catch(() => undefined);
            throw new DurableStateError(
                'Conflict',
                'The durable semantic slot is already occupied.',
            );
        }
        store.put(cloneProtectedRecord(record));
        await completion;
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
        const transaction = this.#database.transaction(storeName, 'readwrite', {
            durability: 'strict',
        });
        const completion = transactionCompletion(transaction);
        const store = transaction.objectStore(storeName);
        const existing = await unknownRequestResult(store.get(expected.id));
        if (
            existing === undefined ||
            !isProtectedRecord(existing) ||
            !protectedRecordsEqual(existing, expected)
        ) {
            transaction.abort();
            await completion.catch(() => undefined);
            throw new DurableStateError(
                'Conflict',
                'The durable predecessor changed before replacement.',
            );
        }
        store.put(cloneProtectedRecord(replacement));
        await completion;
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
        const transaction = this.#database.transaction(
            [replacementStoreName, insertionStoreName],
            'readwrite',
            { durability: 'strict' },
        );
        const completion = transactionCompletion(transaction);
        const replacementStore = transaction.objectStore(replacementStoreName);
        const insertionStore = transaction.objectStore(insertionStoreName);
        const [existingReplacement, existingInsertion] = await Promise.all([
            unknownRequestResult(replacementStore.get(expected.id)),
            unknownRequestResult(insertionStore.get(insertion.id)),
        ]);
        if (
            existingReplacement === undefined ||
            !isProtectedRecord(existingReplacement) ||
            !protectedRecordsEqual(existingReplacement, expected) ||
            existingInsertion !== undefined
        ) {
            transaction.abort();
            await completion.catch(() => undefined);
            throw new DurableStateError(
                'Conflict',
                'The atomic durable predecessor changed or its destination is occupied.',
            );
        }
        replacementStore.put(cloneProtectedRecord(replacement));
        insertionStore.put(cloneProtectedRecord(insertion));
        await completion;
    }
}

export const createProtectedRecord = async (
    identifier: string,
    context: Uint8Array,
    plaintext: Uint8Array,
    rootKey: CryptoKey,
): Promise<ProtectedRecord> => {
    validateRootKey(rootKey);
    if (context.byteLength === 0 || plaintext.byteLength === 0) {
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
    const nonce = crypto.getRandomValues(new Uint8Array(12));
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
