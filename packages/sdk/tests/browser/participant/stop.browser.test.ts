import { afterEach, describe, expect, it, vi } from 'vitest';

import { stopParticipant } from '#packages/sdk/src/participant/worker/stop.js';

const databases: IDBDatabase[] = [];
const names: string[] = [];
const requestResult = <T>(request: IDBRequest<T>): Promise<T> =>
    new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () =>
            reject(request.error ?? new Error('IndexedDB request failed.'));
    });
const openDatabase = async (
    name = `participant-stop-${crypto.randomUUID()}`,
) => {
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => request.result.createObjectStore('stopped');
    const database = await requestResult(request);
    databases.push(database);
    if (!names.includes(name)) names.push(name);
    return database;
};
const readMarker = (database: IDBDatabase) =>
    requestResult<unknown>(
        database.transaction('stopped').objectStore('stopped').get(0),
    );

afterEach(async () => {
    vi.restoreAllMocks();
    for (const database of databases.splice(0)) database.close();
    for (const name of names.splice(0))
        await requestResult(indexedDB.deleteDatabase(name));
});

describe('participant stop persistence in IndexedDB', () => {
    it('confirms a strict commit and readback, including an existing stop marker', async () => {
        const database = await openDatabase();
        await expect(stopParticipant(database)).resolves.toBe('confirmed');
        database.close();
        const reopened = await openDatabase(database.name);
        await expect(readMarker(reopened)).resolves.toBe(true);
        await expect(stopParticipant(reopened)).resolves.toBe('confirmed');
    });

    it('refuses without claiming persistence after a successful put is aborted', async () => {
        const database = await openDatabase();
        const transact = database.transaction.bind(database);
        vi.spyOn(database, 'transaction').mockImplementation(
            (storeNames, mode, options) => {
                const transaction = transact(storeNames, mode, options);
                if (mode === 'readwrite') {
                    const store = transaction.objectStore('stopped');
                    const put = store.put.bind(store);
                    vi.spyOn(store, 'put').mockImplementation((value, key) => {
                        const request = put(value, key);
                        request.addEventListener('success', () =>
                            transaction.abort(),
                        );
                        return request;
                    });
                }
                return transaction;
            },
        );
        await expect(stopParticipant(database)).resolves.toBe('unconfirmed');
        database.close();
        const reopened = await openDatabase(database.name);
        await expect(readMarker(reopened)).resolves.toBeUndefined();
    });

    it('reports an unconfirmed readback even when the stop write committed', async () => {
        const database = await openDatabase();
        const transact = database.transaction.bind(database);
        vi.spyOn(database, 'transaction').mockImplementation(
            (storeNames, mode, options) => {
                const transaction = transact(storeNames, mode, options);
                if (mode === 'readwrite')
                    transaction.addEventListener('complete', () =>
                        database.close(),
                    );
                return transaction;
            },
        );
        await expect(stopParticipant(database)).resolves.toBe('unconfirmed');
        const reopened = await openDatabase(database.name);
        await expect(readMarker(reopened)).resolves.toBe(true);
    });

    it('does not confirm an aborted readback or a marker deleted before readback', async () => {
        for (const fault of ['abort readback', 'delete marker']) {
            const database = await openDatabase();
            const transact = database.transaction.bind(database);
            vi.spyOn(database, 'transaction').mockImplementation(
                (storeNames, mode, options) => {
                    const transaction = transact(storeNames, mode, options);
                    if (mode === 'readonly' && fault === 'abort readback')
                        transaction.abort();
                    if (mode === 'readwrite' && fault === 'delete marker')
                        transaction.addEventListener('complete', () => {
                            transact('stopped', 'readwrite', {
                                durability: 'strict',
                            })
                                .objectStore('stopped')
                                .delete(0);
                        });
                    return transaction;
                },
            );
            await expect(stopParticipant(database)).resolves.toBe(
                'unconfirmed',
            );
            database.close();
            const reopened = await openDatabase(database.name);
            await expect(readMarker(reopened)).resolves.toBe(
                fault === 'abort readback' ? true : undefined,
            );
        }
    });

    it('refuses when the database is unavailable', async () => {
        const database = await openDatabase();
        database.close();
        await expect(stopParticipant(database)).resolves.toBe('unconfirmed');
    });
});
