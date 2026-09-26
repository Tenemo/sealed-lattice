import { afterEach, describe, expect, it } from 'vitest';

import {
    type ParticipantStoredRecord,
    validateParticipantPredecessor,
} from '#packages/sdk/src/participant/worker/predecessor.js';
import { commitParticipantState } from '#packages/sdk/src/participant/worker/state-transaction.js';

const stores = ['head', 'root', 'key', 'stopped', 'data', 'sealed'];
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
// The validator compares the identities its caller derives. These stand-ins
// give the root and record purposes different identities.
const standIn = (purpose: number) => async (bytes: Uint8Array) =>
    new Uint8Array(
        await crypto.subtle.digest('SHA-512', Uint8Array.of(purpose, ...bytes)),
    );
const rootIdentity = standIn(0),
    recordIdentity = standIn(1);

// The root nonce for generation 16, written independently of the helper.
const generationSixteenNonce = Uint8Array.of(
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    16,
);

const fixture = async (generation = 16, rootNonce = generationSixteenNonce) => {
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
        rootContext = Uint8Array.of(29, 41);
    const root = new Uint8Array(
        await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: rootNonce, additionalData: rootContext },
            key,
            manifest,
        ),
    );
    const head = {
        generation,
        hash: Array.from(await rootIdentity(root), (byte) =>
            byte.toString(16).padStart(2, '0'),
        ).join(''),
    };
    const rawKey = crypto.getRandomValues(new Uint8Array(32)),
        additionalData = Uint8Array.of(7, 19),
        plain = Uint8Array.of(2, 3, 5, 7);
    const sealedKey = await crypto.subtle.importKey(
        'raw',
        rawKey,
        'AES-GCM',
        false,
        ['encrypt'],
    );
    const sealed = new Uint8Array(
        await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: new Uint8Array(12), additionalData },
            sealedKey,
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
    initial.objectStore('sealed').add(new Blob([sealed]), [0, 0]);
    await initialized;
    const expected = {
        head,
        manifest,
        rootContext,
        maximumRootBytes: 1024,
        recordStores: ['data', 'sealed'],
        records: [
            {
                store: 'data',
                key: [4, 0],
                byteLength: data.length,
                identity: await recordIdentity(data),
            },
            {
                store: 'sealed',
                key: [0, 0],
                byteLength: sealed.length,
                encryption: { key: rawKey, additionalData },
            },
        ] as ParticipantStoredRecord[],
        identities: { root: rootIdentity, record: recordIdentity },
    };
    const commit = () =>
        commitParticipantState({
            database,
            stores,
            timeoutMilliseconds: 5000,
            validate: (reader) =>
                validateParticipantPredecessor(reader, expected),
            write: (transaction) => {
                transaction.objectStore('sealed').clear();
                transaction
                    .objectStore('head')
                    .put({ ...head, generation: generation + 1 }, 0);
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
    const currentGeneration = async () =>
        (
            (await result(
                database.transaction('head').objectStore('head').get(0),
            )) as typeof head
        ).generation;
    return {
        commit,
        mutate,
        generation: currentGeneration,
        expected,
        sealed,
        root,
        sealedKey: rawKey,
        sealedContext: additionalData,
    };
};

afterEach(async () => {
    for (const database of databases.splice(0)) {
        database.close();
        await result(indexedDB.deleteDatabase(database.name));
    }
});

describe('required predecessor records', () => {
    it('refuses a record described by both a hash and a key', async () => {
        const value = await fixture();
        value.expected.records[1] = {
            ...value.expected.records[1],
            identity: await recordIdentity(value.sealed),
        } as unknown as ParticipantStoredRecord;
        await expect(value.commit()).rejects.toThrow(
            'Invalid predecessor record description.',
        );
        expect(await value.generation()).toBe(16);
    });

    it.each(['hash', 'key', 'context'])(
        'refuses a wrong listed %s',
        async (fault) => {
            const value = await fixture();
            const [data, sealed] = value.expected.records;
            if (fault === 'hash') data.identity![0] ^= 1;
            if (fault === 'key') sealed.encryption!.key[0] ^= 1;
            if (fault === 'context') sealed.encryption!.additionalData[0] ^= 1;
            await expect(value.commit()).rejects.toThrow();
            expect(await value.generation()).toBe(16);
        },
    );
    it('authenticates old ciphertexts and hashes before retiring a sealed record', async () => {
        const value = await fixture();
        await value.commit();
        expect(await value.generation()).toBe(17);
    });

    it('hashes and decrypts exactly a stored root view with nonzero offset', async () => {
        const value = await fixture();
        const allocation = new Uint8Array(value.root.length + 6).fill(211);
        allocation.set(value.root, 3);
        await value.mutate('root', (store) =>
            store.put(allocation.subarray(3, allocation.length - 3), 0),
        );
        await value.commit();
        expect(await value.generation()).toBe(17);
    });

    it('rejects a shifted root view even when its backing allocation contains the original', async () => {
        const value = await fixture();
        const allocation = new Uint8Array(value.root.length + 6).fill(223);
        allocation.set(value.root, 3);
        await value.mutate('root', (store) =>
            store.put(allocation.subarray(2, allocation.length - 4), 0),
        );
        await expect(value.commit()).rejects.toThrow('authority changed');
        expect(await value.generation()).toBe(16);
    });

    it.each([
        'missing sealed record',
        'changed sealed record',
        'changed data',
        'unexpected record',
        'stopped',
        'wrong context',
        'changed manifest',
    ])(
        'refuses %s while preserving the preceding generation',
        async (fault) => {
            const value = await fixture();
            if (fault === 'missing sealed record')
                await value.mutate('sealed', (store) => store.delete([0, 0]));
            if (fault === 'changed sealed record') {
                value.sealed[0] ^= 1;
                await value.mutate('sealed', (store) =>
                    store.put(new Blob([value.sealed]), [0, 0]),
                );
            }
            if (fault === 'changed data')
                await value.mutate('data', (store) =>
                    store.put(new Blob([Uint8Array.of(101, 107)]), [4, 0]),
                );
            if (fault === 'unexpected record')
                await value.mutate('sealed', (store) =>
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

describe('predecessor root nonce', () => {
    it('authenticates a root past one byte of generations with the full counter nonce', async () => {
        const value = await fixture(
            256,
            Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0),
        );
        await value.commit();
        expect(await value.generation()).toBe(257);
    });

    it('refuses a root sealed under the wrapped single-byte nonce', async () => {
        const value = await fixture(256, new Uint8Array(12));
        await expect(value.commit()).rejects.toThrow();
        expect(await value.generation()).toBe(256);
    });

    it.each([-1, 1.5, Number.NaN, 2 ** 53])(
        'refuses the invalid generation %s before reading the root',
        async (generation) => {
            const value = await fixture(generation);
            await expect(value.commit()).rejects.toThrow(
                'Invalid predecessor generation.',
            );
        },
    );
});

describe('predecessor record keys', () => {
    const addSecondSealed = async (
        value: Awaited<ReturnType<typeof fixture>>,
        rawKey: Uint8Array,
    ) => {
        const key = await crypto.subtle.importKey(
            'raw',
            new Uint8Array(rawKey),
            'AES-GCM',
            false,
            ['encrypt'],
        );
        const sealed = new Uint8Array(
            await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv: new Uint8Array(12),
                    additionalData: value.sealedContext,
                },
                key,
                Uint8Array.of(11, 13, 17, 19),
            ),
        );
        await value.mutate('sealed', (store) =>
            store.add(new Blob([sealed]), [0, 1]),
        );
        value.expected.records.push({
            store: 'sealed',
            key: [0, 1],
            byteLength: sealed.length,
            encryption: {
                key: Uint8Array.from(rawKey),
                additionalData: value.sealedContext,
            },
        });
    };

    it('accepts two zero-nonce records under distinct keys', async () => {
        const value = await fixture();
        await addSecondSealed(
            value,
            crypto.getRandomValues(new Uint8Array(32)),
        );
        await value.commit();
        expect(await value.generation()).toBe(17);
    });

    it('refuses two zero-nonce records under one key', async () => {
        const value = await fixture();
        await addSecondSealed(value, value.sealedKey);
        await expect(value.commit()).rejects.toThrow(
            'Invalid predecessor record description.',
        );
        expect(await value.generation()).toBe(16);
    });
});
