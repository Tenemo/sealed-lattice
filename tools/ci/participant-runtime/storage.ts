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

export const openParticipantDatabase = async (): Promise<IDBDatabase> => {
    const request = indexedDB.open('sealed-lattice-participant', 1);
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
