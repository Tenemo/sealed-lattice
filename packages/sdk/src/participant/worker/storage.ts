// The participant's origin-local database. The key, root and head stores hold
// the single authenticated root; every other store holds records that root
// references by hash or by record key.
export const participantStores = [
    'key',
    'root',
    'head',
    'stopped',
    'data',
    'contribution',
    'checkpoint',
    'ballot',
    'close',
    'release',
] as const;

export type ParticipantStore = (typeof participantStores)[number];

export const participantRecordStores = [
    'data',
    'contribution',
    'checkpoint',
    'ballot',
    'close',
    'release',
] as const;

export type ParticipantHead = Readonly<{ generation: number; hash: string }>;

// One origin holds each participant under its own namespace, which names every
// database and lock of that participant.
export const participantNamespacePattern =
    /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/u;

export const namespacedName = (name: string, namespace: string) =>
    name + '/' + namespace;

export const participantDatabaseName = (namespace: string) =>
    namespacedName('sealed-lattice-participant', namespace);

const requestResult = <Value>(request: IDBRequest<Value>) =>
    new Promise<Value>((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () =>
            reject(request.error ?? new Error('Local record request failed.'));
    });

const transactionCompletion = (transaction: IDBTransaction) =>
    new Promise<void>((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onabort = () =>
            reject(
                transaction.error ?? new Error('Local transaction aborted.'),
            );
    });

export const openParticipantDatabase = async (
    namespace: string,
): Promise<IDBDatabase> => {
    const request = indexedDB.open(participantDatabaseName(namespace), 1);
    request.onupgradeneeded = () => {
        for (const store of participantStores)
            request.result.createObjectStore(store);
    };
    const database = await requestResult(request);
    const names = [...database.objectStoreNames].sort().join(',');
    if (names !== [...participantStores].sort().join(',')) {
        database.close();
        throw new Error('Unexpected participant store inventory.');
    }
    return database;
};

export const readParticipantValue = async (
    database: IDBDatabase,
    store: ParticipantStore,
    key: IDBValidKey,
): Promise<unknown> => {
    const transaction = database.transaction(store, 'readonly');
    const done = transactionCompletion(transaction);
    const value = await requestResult<unknown>(
        transaction.objectStore(store).get(key),
    );
    await done;
    return value;
};

// Adds records that no root references yet in one strict transaction. Only
// generated output is staged this way; the next root lists it and its
// transition checks every staged record before it commits.
export const addParticipantRecords = async (
    database: IDBDatabase,
    store: ParticipantStore,
    records: readonly Readonly<{ key: IDBValidKey; bytes: Uint8Array }>[],
): Promise<void> => {
    const transaction = database.transaction(store, 'readwrite', {
        durability: 'strict',
    });
    const done = transactionCompletion(transaction);
    for (const record of records)
        transaction
            .objectStore(store)
            .add(new Blob([new Uint8Array(record.bytes)]), record.key);
    await done;
};

// Deletes staged records that no root references, in one strict
// transaction: a whole store, or the keys of a range in it.
export const discardStagedRecords = async (
    database: IDBDatabase,
    ranges: readonly Readonly<{
        store: ParticipantStore;
        keys?: IDBKeyRange;
    }>[],
): Promise<void> => {
    const transaction = database.transaction(
        ranges.map((range) => range.store),
        'readwrite',
        { durability: 'strict' },
    );
    const done = transactionCompletion(transaction);
    for (const { store, keys } of ranges)
        if (keys === undefined) transaction.objectStore(store).clear();
        else transaction.objectStore(store).delete(keys);
    await done;
};

// One consistent read of the root authority and every store's cardinality.
export const snapshotParticipant = async (database: IDBDatabase) => {
    const transaction = database.transaction(
        [...participantStores],
        'readonly',
    );
    const done = transactionCompletion(transaction);
    const [key, root, head, ...counts] = await Promise.all([
        requestResult<unknown>(transaction.objectStore('key').get(0)),
        requestResult<unknown>(transaction.objectStore('root').get(0)),
        requestResult<unknown>(transaction.objectStore('head').get(0)),
        ...participantStores.map((store) =>
            requestResult(transaction.objectStore(store).count()),
        ),
    ]);
    await done;
    return {
        key,
        root,
        head,
        counts: Object.fromEntries(
            participantStores.map((store, index) => [store, counts[index]]),
        ) as Record<ParticipantStore, number>,
    };
};

// Whether the namespace holds nothing: no participant and no stop marker.
export const isEmptyParticipant = async (database: IDBDatabase) => {
    const { counts } = await snapshotParticipant(database);
    return participantStores.every((store) => counts[store] === 0);
};

export const isParticipantHead = (value: unknown): value is ParticipantHead =>
    typeof value === 'object' &&
    value !== null &&
    'generation' in value &&
    'hash' in value &&
    Object.keys(value).length === 2 &&
    Number.isSafeInteger(value.generation) &&
    typeof value.hash === 'string' &&
    /^[0-9a-f]{128}$/u.test(value.hash);

export const isRootKey = (value: unknown): value is CryptoKey =>
    value instanceof CryptoKey &&
    value.type === 'secret' &&
    !value.extractable &&
    value.algorithm.name === 'AES-GCM' &&
    'length' in value.algorithm &&
    value.algorithm.length === 256 &&
    value.usages.slice().sort().join(',') === 'decrypt,encrypt';
