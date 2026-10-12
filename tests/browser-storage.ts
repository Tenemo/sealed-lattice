// Fixture plumbing stays independent from the participant's storage code.
// Tests retain their own schemas, mutations and failure injection.
export const fixtureRequest = <Value>(
    request: IDBRequest<Value>,
    failureMessage = 'Fixture read failed.',
): Promise<Value> =>
    new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () =>
            reject(request.error ?? new Error(failureMessage));
    });

export const writeFixtureTransaction = (
    database: IDBDatabase,
    stores: string | string[],
    change: (transaction: IDBTransaction) => void,
    options?: IDBTransactionOptions,
    failureMessage = 'Fixture write failed.',
): Promise<void> =>
    new Promise((resolve, reject) => {
        const transaction =
            options === undefined
                ? database.transaction(stores, 'readwrite')
                : database.transaction(stores, 'readwrite', options);
        transaction.oncomplete = () => resolve();
        transaction.onabort = () =>
            reject(transaction.error ?? new Error(failureMessage));
        change(transaction);
    });

export const writeFixtureStore = (
    database: IDBDatabase,
    store: string,
    change: (objects: IDBObjectStore) => void,
    options?: IDBTransactionOptions,
    failureMessage?: string,
) =>
    writeFixtureTransaction(
        database,
        store,
        (transaction) => change(transaction.objectStore(store)),
        options,
        failureMessage,
    );
