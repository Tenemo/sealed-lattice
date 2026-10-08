import { StorageFailure, UnrecognizedState } from './failures.js';

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

// The head names the committed root by generation and identity, and the
// runtime whose worker committed it, in plaintext, so that another runtime
// can refuse the participant before any authority starts.
export type ParticipantHead = Readonly<{
    generation: number;
    hash: string;
    runtime: string;
}>;

// One origin holds each participant under its own namespace, which names every
// database and lock of that participant.
export const participantNamespacePattern =
    /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/u;

export const namespacedName = (name: string, namespace: string) =>
    name + '/' + namespace;

export const participantDatabaseName = (namespace: string) =>
    namespacedName('sealed-lattice-participant', namespace);

// The public caches beside the participant's database, which hold no
// authority and which an operation rebuilds from public records when they are
// lost: the verified setup's aggregate and the target the participant
// evaluated.
export const setupCacheName = 'sealed-lattice-setup';
export const evaluatedTargetName = 'sealed-lattice-evaluated-target';
// The values an evaluation spills and the records of its keys, which each
// evaluation clears before it starts and after the target exists.
export const publicEvaluationName = 'sealed-lattice-public-evaluation';

// Deletes a verification's public working storage: its aggregate cache and
// its evaluation's values and key records. A database that another
// connection holds is deleted once that connection closes. The storage
// holds no authority and the next verification clears it before use, so a
// deletion the browser refuses leaves nothing to report.
export const deleteWorkingStorage = async (namespace: string) => {
    for (const name of [setupCacheName, publicEvaluationName])
        await new Promise<void>((resolve) => {
            const request = indexedDB.deleteDatabase(
                namespacedName(name, namespace),
            );
            request.onsuccess = () => resolve();
            request.onerror = () => resolve();
            request.onblocked = () => resolve();
        });
};

// Settles with a request's result. A failed request rejects with the
// caller's failure, or else with its own error.
export const requestResult = <Value>(
    request: IDBRequest<Value>,
    failure?: () => Error,
) =>
    new Promise<Value>((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () =>
            reject(
                failure?.() ??
                    request.error ??
                    new Error('Local record request failed.'),
            );
    });

// Settles once a transaction commits. An aborted transaction rejects with the
// caller's failure, or else with its own error.
export const transactionCompletion = (
    transaction: IDBTransaction,
    failure?: () => Error,
) =>
    new Promise<void>((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onabort = () =>
            reject(
                failure?.() ??
                    transaction.error ??
                    new Error('Local transaction aborted.'),
            );
    });

// Keeps a promise that is awaited later, while other work continues, from
// reporting an unhandled rejection meanwhile.
export const awaitLater = <Value>(promise: Promise<Value>) => {
    void promise.catch(() => undefined);
    return promise;
};

export const openParticipantDatabase = async (
    namespace: string,
): Promise<IDBDatabase> => {
    const request = indexedDB.open(participantDatabaseName(namespace), 1);
    request.onupgradeneeded = () => {
        for (const store of participantStores)
            request.result.createObjectStore(store);
    };
    let database: IDBDatabase;
    try {
        database = await requestResult(request);
    } catch (error) {
        // A database of a later version is not one this SDK created.
        if (error instanceof DOMException && error.name === 'VersionError')
            throw new UnrecognizedState(
                'The participant database has another version.',
            );
        throw error;
    }
    const names = [...database.objectStoreNames].sort().join(',');
    if (names !== [...participantStores].sort().join(',')) {
        database.close();
        throw new UnrecognizedState('Unexpected participant store inventory.');
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
// transition checks every staged record before it commits. A transaction the
// origin's quota aborts adds nothing.
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
    try {
        await done;
    } catch (error) {
        if (
            error instanceof DOMException &&
            error.name === 'QuotaExceededError'
        )
            throw new StorageFailure(
                'The origin lacks room for staged participant records.',
            );
        throw error;
    }
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

const isDigest = (value: unknown) =>
    typeof value === 'string' && /^[0-9a-f]{128}$/u.test(value);

export const isParticipantHead = (value: unknown): value is ParticipantHead =>
    typeof value === 'object' &&
    value !== null &&
    'generation' in value &&
    'hash' in value &&
    'runtime' in value &&
    Object.keys(value).length === 3 &&
    Number.isSafeInteger(value.generation) &&
    isDigest(value.hash) &&
    isDigest(value.runtime);

// Which runtime created the namespace's participant, read before any
// authority starts: none for an empty namespace, or the runtime a head names.
// Any other state leaves the question to root authentication, which stops a
// participant whose authority is damaged.
export const storedRuntime = async (
    database: IDBDatabase,
): Promise<
    | Readonly<{ status: 'empty' }>
    | Readonly<{ status: 'named'; runtime: string }>
    | Readonly<{ status: 'unnamed' }>
> => {
    const { head, counts } = await snapshotParticipant(database);
    if (participantStores.every((store) => counts[store] === 0))
        return { status: 'empty' };
    return counts.head === 1 && isParticipantHead(head)
        ? { status: 'named', runtime: head.runtime }
        : { status: 'unnamed' };
};

export const isRootKey = (value: unknown): value is CryptoKey =>
    value instanceof CryptoKey &&
    value.type === 'secret' &&
    !value.extractable &&
    value.algorithm.name === 'AES-GCM' &&
    'length' in value.algorithm &&
    value.algorithm.length === 256 &&
    value.usages.slice().sort().join(',') === 'decrypt,encrypt';
