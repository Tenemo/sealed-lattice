import { afterEach, describe, expect, it } from 'vitest';

import {
    openParticipantDatabase,
    participantDatabaseName,
    snapshotParticipant,
} from '#packages/sdk/src/participant/worker/storage/database.js';
import type { ParticipantStore } from '#packages/sdk/src/participant/worker/storage/database.js';
import {
    guardDelivery,
    inspectRetainedAuthority,
} from '#packages/sdk/src/participant/worker/storage/delivery.js';
import type { RetainedAuthority } from '#packages/sdk/src/participant/worker/storage/delivery.js';
import {
    createRootKey,
    sealRoot,
} from '#packages/sdk/src/participant/worker/storage/root.js';

const databases: IDBDatabase[] = [];
const namespaces: string[] = [];
const requestResult = <T>(request: IDBRequest<T>): Promise<T> =>
    new Promise((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () =>
            reject(request.error ?? new Error('IndexedDB request failed.'));
    });
const write = (
    database: IDBDatabase,
    store: ParticipantStore,
    change: (objects: IDBObjectStore) => void,
) =>
    new Promise<void>((resolve, reject) => {
        const transaction = database.transaction(store, 'readwrite');
        transaction.oncomplete = () => resolve();
        transaction.onabort = () =>
            reject(transaction.error ?? new Error('Fixture write aborted.'));
        change(transaction.objectStore(store));
    });
// The inspection compares the root identity its caller derives; this
// stand-in differs from the participant module's identity but is also a
// collision-resistant digest of the sealed root.
const rootIdentity = async (bytes: Uint8Array) =>
    new Uint8Array(
        await crypto.subtle.digest('SHA-512', new Uint8Array(bytes)),
    );
const hexadecimal = (bytes: Uint8Array) =>
    Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('');
const rootContext = Uint8Array.of(80, 79, 76, 49, 7);
const generation = 29;
const runtime = 'c4'.repeat(64);

// A participant database holding one sealed root, two data records and three
// release records, and the authority a delivery expects of it.
const fixture = async () => {
    const namespace = `delivery-${crypto.randomUUID()}`;
    namespaces.push(namespace);
    const database = await openParticipantDatabase(namespace);
    databases.push(database);
    const key = await createRootKey();
    const plaintext = crypto.getRandomValues(new Uint8Array(96));
    const sealed = await sealRoot(key, generation, rootContext, plaintext);
    const head = {
        generation,
        hash: hexadecimal(await rootIdentity(sealed)),
        runtime,
    };
    await write(database, 'key', (store) => store.put(key, 0));
    await write(database, 'root', (store) => store.put(sealed, 0));
    await write(database, 'head', (store) => store.put(head, 0));
    await write(database, 'data', (store) => {
        store.put(new Blob([Uint8Array.of(1)]), [0, 0]);
        store.put(new Blob([Uint8Array.of(2)]), [1, 0]);
    });
    await write(database, 'release', (store) => {
        for (const index of [0, 1, 2])
            store.put(new Blob([Uint8Array.of(index)]), index);
    });
    const { counts } = await snapshotParticipant(database);
    const expected: RetainedAuthority = {
        head,
        plaintext,
        rootContext,
        counts,
    };
    return { database, key, plaintext, expected };
};
const inspect = (fixed: Awaited<ReturnType<typeof fixture>>) =>
    inspectRetainedAuthority(fixed.database, fixed.expected, rootIdentity);
const changed = 'The participant authority changed during delivery.';

afterEach(async () => {
    for (const database of databases.splice(0)) database.close();
    for (const namespace of namespaces.splice(0))
        await requestResult(
            indexedDB.deleteDatabase(participantDatabaseName(namespace)),
        );
});

describe('retained authority inspection in IndexedDB', () => {
    it('accepts the unchanged root, head, key and record counts repeatedly', async () => {
        const fixed = await fixture();
        await expect(inspect(fixed)).resolves.toBeUndefined();
        await expect(inspect(fixed)).resolves.toBeUndefined();
    });

    it('refuses every loss, replacement or addition of retained state', async () => {
        const faults: Record<
            string,
            (fixed: Awaited<ReturnType<typeof fixture>>) => Promise<void>
        > = {
            'root deleted': (fixed) =>
                write(fixed.database, 'root', (store) => store.delete(0)),
            'key deleted': (fixed) =>
                write(fixed.database, 'key', (store) => store.delete(0)),
            'head deleted': (fixed) =>
                write(fixed.database, 'head', (store) => store.delete(0)),
            'stop marker written': (fixed) =>
                write(fixed.database, 'stopped', (store) => store.put(true, 0)),
            'release record deleted': (fixed) =>
                write(fixed.database, 'release', (store) => store.delete(1)),
            'data record deleted': (fixed) =>
                write(fixed.database, 'data', (store) => store.delete([1, 0])),
            'close record added': (fixed) =>
                write(fixed.database, 'close', (store) =>
                    store.put(new Blob([Uint8Array.of(9)]), 0),
                ),
            'root replaced with its head': async (fixed) => {
                const other = await sealRoot(
                    fixed.key,
                    generation,
                    rootContext,
                    crypto.getRandomValues(new Uint8Array(96)),
                );
                await write(fixed.database, 'root', (store) =>
                    store.put(other, 0),
                );
                const hash = hexadecimal(await rootIdentity(other));
                await write(fixed.database, 'head', (store) =>
                    store.put({ generation, hash, runtime }, 0),
                );
            },
            'root replaced under its head': async (fixed) => {
                const other = await sealRoot(
                    fixed.key,
                    generation,
                    rootContext,
                    crypto.getRandomValues(new Uint8Array(96)),
                );
                await write(fixed.database, 'root', (store) =>
                    store.put(other, 0),
                );
            },
            'key replaced': async (fixed) => {
                const other = await createRootKey();
                await write(fixed.database, 'key', (store) =>
                    store.put(other, 0),
                );
            },
            'head generation changed': (fixed) =>
                write(fixed.database, 'head', (store) =>
                    store.put(
                        {
                            generation: generation - 1,
                            hash: fixed.expected.head.hash,
                            runtime,
                        },
                        0,
                    ),
                ),
            'head runtime changed': (fixed) =>
                write(fixed.database, 'head', (store) =>
                    store.put(
                        {
                            generation,
                            hash: fixed.expected.head.hash,
                            runtime: 'd5'.repeat(64),
                        },
                        0,
                    ),
                ),
        };
        for (const [name, fault] of Object.entries(faults)) {
            const fixed = await fixture();
            await fault(fixed);
            await expect(inspect(fixed), name).rejects.toThrow(changed);
        }
    });

    it('refuses a root whose key opens it to other bytes under the same head', async () => {
        const fixed = await fixture();
        const expected = {
            ...fixed.expected,
            plaintext: fixed.plaintext.map((value) => value ^ 1),
        };
        await expect(
            inspectRetainedAuthority(fixed.database, expected, rootIdentity),
        ).rejects.toThrow(changed);
    });

    it('stops a delivery when state disappears after a successful transfer', async () => {
        const fixed = await fixture();
        const delivery = await guardDelivery(() => inspect(fixed));
        const sent: string[] = [];
        const copy = Uint8Array.of(5, 6);
        await expect(
            delivery.transfer(async () => {
                sent.push('first');
                await write(fixed.database, 'root', (store) => store.delete(0));
            }, copy),
        ).rejects.toThrow(changed);
        expect(copy).toEqual(Uint8Array.of(0, 0));
        expect(sent).toEqual(['first']);
    });
});
