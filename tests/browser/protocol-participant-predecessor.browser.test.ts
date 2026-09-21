import { afterEach, describe, expect, it } from 'vitest';

import { validateParticipantPredecessor } from '#tools/ci/protocol-participant-predecessor.js';
import { commitParticipantState } from '#tools/ci/protocol-participant-state-transaction.js';

const stores = ['head', 'root', 'key', 'stopped', 'data', 'journal'];
const databases: IDBDatabase[] = [];
const result = <Value>(request: IDBRequest<Value>) =>
    new Promise<Value>((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () =>
            reject(request.error ?? new Error('Record read failed.'));
    });
const done = (transaction: IDBTransaction) =>
    new Promise<void>((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onabort = () =>
            reject(
                transaction.error ?? new Error('Fixture transaction aborted.'),
            );
    });
const hash = async (bytes: Uint8Array) =>
    new Uint8Array(
        await crypto.subtle.digest('SHA-512', new Uint8Array(bytes)),
    );

const fixture = async () => {
    const opening = indexedDB.open(`predecessor-${crypto.randomUUID()}`, 1);
    opening.onupgradeneeded = () => {
        for (const name of stores) opening.result.createObjectStore(name);
    };
    const database = await result(opening);
    databases.push(database);
    const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
    );
    const manifest = Uint8Array.of(13, 5, 67),
        rootContext = Uint8Array.of(29, 41),
        iv = new Uint8Array(12);
    iv[11] = 16;
    const root = new Uint8Array(
        await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, additionalData: rootContext },
            key,
            manifest,
        ),
    );
    const head = {
        generation: 16,
        hash: Array.from(await hash(root), (byte) =>
            byte.toString(16).padStart(2, '0'),
        ).join(''),
    };
    const rawKey = crypto.getRandomValues(new Uint8Array(32)),
        additionalData = Uint8Array.of(7, 19),
        plain = Uint8Array.of(2, 3, 5, 7);
    const journalKey = await crypto.subtle.importKey(
        'raw',
        rawKey,
        'AES-GCM',
        false,
        ['encrypt'],
    );
    const journal = new Uint8Array(
        await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: new Uint8Array(12), additionalData },
            journalKey,
            plain,
        ),
    );
    const data = Uint8Array.of(101, 103);
    const initial = database.transaction(stores, 'readwrite'),
        initialized = done(initial);
    for (const [name, value] of [
        ['head', head],
        ['root', root],
        ['key', key],
    ] as const)
        initial.objectStore(name).add(value, 0);
    initial.objectStore('data').add(new Blob([data]), [4, 0]);
    initial.objectStore('journal').add(new Blob([journal]), [0, 0]);
    await initialized;
    const expected = {
        head,
        manifest,
        rootContext,
        maximumRootBytes: 1024,
        recordStores: ['data', 'journal'],
        records: [
            {
                store: 'data',
                key: [4, 0],
                byteLength: data.length,
                sha512: await hash(data),
            },
            {
                store: 'journal',
                key: [0, 0],
                byteLength: journal.length,
                encryption: { key: rawKey, additionalData },
            },
        ],
    };
    const commit = () =>
        commitParticipantState({
            database,
            stores,
            timeoutMilliseconds: 5000,
            validate: (reader) =>
                validateParticipantPredecessor(reader, expected),
            write: (transaction) => {
                transaction.objectStore('journal').clear();
                transaction
                    .objectStore('head')
                    .put({ ...head, generation: 17 }, 0);
            },
        });
    const mutate = async (
        store: string,
        apply: (value: IDBObjectStore) => void,
    ) => {
        const transaction = database.transaction(store, 'readwrite'),
            completed = done(transaction);
        apply(transaction.objectStore(store));
        await completed;
    };
    const generation = async () =>
        (
            (await result(
                database.transaction('head').objectStore('head').get(0),
            )) as typeof head
        ).generation;
    return { commit, mutate, generation, expected, journal };
};

afterEach(async () => {
    for (const database of databases.splice(0)) {
        database.close();
        await result(indexedDB.deleteDatabase(database.name));
    }
});

describe('required predecessor records', () => {
    it('authenticates old ciphertexts and hashes before retiring the journal', async () => {
        const value = await fixture();
        await value.commit();
        expect(await value.generation()).toBe(17);
    });

    it.each([
        'missing journal',
        'changed journal',
        'changed data',
        'unexpected record',
        'stopped',
        'wrong context',
        'changed manifest',
    ])(
        'refuses %s while preserving the preceding generation',
        async (fault) => {
            const value = await fixture();
            if (fault === 'missing journal')
                await value.mutate('journal', (store) => store.delete([0, 0]));
            if (fault === 'changed journal') {
                value.journal[0] ^= 1;
                await value.mutate('journal', (store) =>
                    store.put(new Blob([value.journal]), [0, 0]),
                );
            }
            if (fault === 'changed data')
                await value.mutate('data', (store) =>
                    store.put(new Blob([Uint8Array.of(101, 107)]), [4, 0]),
                );
            if (fault === 'unexpected record')
                await value.mutate('journal', (store) =>
                    store.add(new Blob([Uint8Array.of(1)]), [0, 1]),
                );
            if (fault === 'stopped')
                await value.mutate('stopped', (store) => store.add(true, 0));
            if (fault === 'wrong context')
                value.expected.records[1].encryption!.additionalData[0] ^= 1;
            if (fault === 'changed manifest') value.expected.manifest[0] ^= 1;
            await expect(value.commit()).rejects.toThrow();
            expect(await value.generation()).toBe(16);
        },
    );
});
