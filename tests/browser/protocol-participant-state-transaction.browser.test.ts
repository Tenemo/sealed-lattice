import { afterEach, describe, expect, it, vi } from 'vitest';

import {
    commitParticipantState,
    type ParticipantTransactionReader,
} from '#tools/ci/protocol-participant-state-transaction.js';

const databases: IDBDatabase[] = [];
const stores = ['head', 'root', 'key', 'records'];
const requestResult = <Value>(request: IDBRequest<Value>) =>
    new Promise<Value>((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () =>
            reject(request.error ?? new Error('IndexedDB request failed.'));
    });
const completed = (transaction: IDBTransaction) =>
    new Promise<void>((resolve, reject) => {
        transaction.oncomplete = () => resolve();
        transaction.onabort = () =>
            reject(transaction.error ?? new Error('IndexedDB write aborted.'));
        transaction.onerror = () => {};
    });
const fixture = async () => {
    const opening = indexedDB.open(`root-transition-${crypto.randomUUID()}`, 1);
    opening.onupgradeneeded = () => {
        for (const store of stores) opening.result.createObjectStore(store);
    };
    const database = await requestResult(opening);
    databases.push(database);
    const key = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
    );
    const plaintext = Uint8Array.of(1, 7, 19),
        associatedData = Uint8Array.of(31, 43),
        iv = new Uint8Array(12);
    const root = new Uint8Array(
        await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv, additionalData: associatedData },
            key,
            plaintext,
        ),
    );
    const initial = database.transaction(stores, 'readwrite'),
        done = completed(initial);
    initial.objectStore('head').put(18, 0);
    initial.objectStore('key').put(key, 0);
    initial.objectStore('root').put(root, 0);
    initial.objectStore('records').put(new Blob([Uint8Array.of(5, 6)]), 0);
    await done;
    const validate = async (reader: ParticipantTransactionReader) => {
        expect(await reader.get('head', 0)).toBe(18);
        const storedRoot = await reader.get('root', 0),
            storedKey = await reader.get('key', 0);
        if (
            !(storedRoot instanceof Uint8Array) ||
            !(storedKey instanceof CryptoKey)
        )
            throw new Error('Missing root authority.');
        expect(storedRoot).toEqual(root);
        const opened = new Uint8Array(
            await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv, additionalData: associatedData },
                storedKey,
                new Uint8Array(storedRoot),
            ),
        );
        expect(opened).toEqual(plaintext);
        expect(await reader.count('records')).toBe(1);
        const record = await reader.get('records', 0);
        if (!(record instanceof Blob)) throw new Error('Missing old record.');
        expect(new Uint8Array(await record.arrayBuffer())).toEqual(
            Uint8Array.of(5, 6),
        );
    };
    const head = () =>
        requestResult(database.transaction('head').objectStore('head').get(0));
    const commit = (
        check = validate,
        write = (transaction: IDBTransaction) => {
            transaction.objectStore('head').put(19, 0);
            transaction.objectStore('records').delete(0);
        },
        timeoutMilliseconds = 5000,
    ) =>
        commitParticipantState({
            database,
            stores,
            validate: check,
            write,
            timeoutMilliseconds,
        });
    return { database, validate, commit, head };
};

afterEach(async () => {
    vi.restoreAllMocks();
    for (const database of databases.splice(0)) {
        database.close();
        await requestResult(indexedDB.deleteDatabase(database.name));
    }
});

describe('authenticated participant state transactions', () => {
    it('keeps the transaction active through delayed WebCrypto and Blob reads before retirement', async () => {
        const { commit, validate, head } = await fixture();
        await commit(async (reader) => {
            await new Promise((resolve) => setTimeout(resolve, 20));
            await validate(reader);
        });
        expect(await head()).toBe(19);
    });

    it.each(['root', 'key', 'records'])(
        'refuses a missing predecessor %s without successor writes',
        async (store) => {
            const { database, commit, head } = await fixture();
            const transaction = database.transaction(store, 'readwrite'),
                done = completed(transaction);
            transaction.objectStore(store).delete(0);
            await done;
            await expect(commit()).rejects.toThrow();
            expect(await head()).toBe(18);
        },
    );

    it('authenticates logical key identity rather than accepting a same-shaped replacement', async () => {
        const { database, commit, head } = await fixture();
        const replacement = await crypto.subtle.generateKey(
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt'],
        );
        const transaction = database.transaction('key', 'readwrite'),
            done = completed(transaction);
        transaction.objectStore('key').put(replacement, 0);
        await done;
        await expect(commit()).rejects.toThrow();
        expect(await head()).toBe(18);
    });

    it('serializes a competing mutation after the authenticated commit', async () => {
        const { database, commit, validate, head } = await fixture();
        const order: string[] = [];
        let competing: Promise<void> | undefined;
        await commit(
            async (reader) => {
                await validate(reader);
                const transaction = database.transaction('root', 'readwrite');
                competing = completed(transaction).then(() => {
                    order.push('competing');
                });
                transaction.objectStore('root').delete(0);
                await new Promise((resolve) => setTimeout(resolve, 20));
                await validate(reader);
                order.push('validated');
            },
            (transaction) => {
                order.push('write');
                transaction.objectStore('head').put(19, 0);
            },
        );
        await competing;
        expect(order).toEqual(['validated', 'write', 'competing']);
        expect(await head()).toBe(19);
    });

    it('rolls back writes when the commit callback fails', async () => {
        const { commit, validate, head } = await fixture();
        await expect(
            commit(validate, (transaction) => {
                transaction.objectStore('head').put(19, 0);
                throw new Error('Injected completion failure.');
            }),
        ).rejects.toThrow('Injected completion failure');
        expect(await head()).toBe(18);
    });

    it('bounds stalled validation and never writes when it later resumes', async () => {
        const { commit, head } = await fixture();
        let resume!: () => void;
        const waiting = new Promise<void>((resolve) => {
            resume = resolve;
        });
        await expect(
            commit(async () => waiting, undefined, 10),
        ).rejects.toThrow('deadline');
        resume();
        await new Promise((resolve) => setTimeout(resolve, 20));
        expect(await head()).toBe(18);
    });

    it('aborts a late validation read invoked from the write callback', async () => {
        const { commit, validate, head } = await fixture();
        let retained!: ParticipantTransactionReader;
        await expect(
            commit(
                async (reader) => {
                    retained = reader;
                    await validate(reader);
                },
                (transaction) => {
                    transaction.objectStore('head').put(19, 0);
                    void retained.get('head', 0);
                },
            ),
        ).rejects.toThrow('validation already ended');
        expect(await head()).toBe(18);
    });

    it('aborts even when a write request error is handled by its caller', async () => {
        const { commit, validate, head } = await fixture();
        await expect(
            commit(validate, (transaction) => {
                transaction.objectStore('head').put(19, 0);
                const duplicate = transaction.objectStore('head').add(20, 0);
                duplicate.onerror = (event) => event.preventDefault();
            }),
        ).rejects.toThrow();
        expect(await head()).toBe(18);
    });

    it('propagates discarded read failures through the transaction without an unhandled rejection', async () => {
        const { commit, head } = await fixture();
        await expect(
            commit((reader) => {
                void reader.get('outside-scope', 0);
                return Promise.resolve();
            }),
        ).rejects.toThrow();
        expect(await head()).toBe(18);
    });

    it('rejects an asynchronous write callback and observes its later failure', async () => {
        const { commit, validate, head } = await fixture();
        const invalidWrite: unknown = async (transaction: IDBTransaction) => {
            transaction.objectStore('head').put(19, 0);
            await Promise.resolve();
            throw new Error('Asynchronous write failed.');
        };
        await expect(
            commit(
                validate,
                invalidWrite as (transaction: IDBTransaction) => void,
            ),
        ).rejects.toThrow('writes must be synchronous');
        expect(await head()).toBe(18);
    });

    it('clears the validation deadline before queuing writes', async () => {
        const { commit, validate, head } = await fixture();
        const clear = vi.spyOn(globalThis, 'clearTimeout');
        await commit(validate, (transaction) => {
            expect(clear).toHaveBeenCalled();
            transaction.objectStore('head').put(19, 0);
        });
        expect(await head()).toBe(19);
    });

    it('refuses unsupported strict durability before validation or writes', async () => {
        const { database, commit, head } = await fixture();
        const transact = database.transaction.bind(database);
        vi.spyOn(database, 'transaction').mockImplementation(
            (names, mode, options) =>
                transact(names, mode, { ...options, durability: 'relaxed' }),
        );
        await expect(commit()).rejects.toThrow('Strict participant durability');
        expect(await head()).toBe(18);
    });
});
