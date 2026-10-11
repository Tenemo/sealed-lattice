import { afterEach, describe, expect, it } from 'vitest';

import type { PublicProfileContext } from '#packages/sdk/src/participant/worker/module/context.js';
import {
    ModuleFailure,
    PublicInputFailure,
} from '#packages/sdk/src/participant/worker/shared/failures.js';
import { deliverBallotKey } from '#packages/sdk/src/participant/worker/stages/ballot/ballot.js';
import {
    deliverFinalAggregate,
    readFinalAggregate,
} from '#packages/sdk/src/participant/worker/stages/setup/setup-cache.js';
import {
    namespacedName,
    setupCacheName,
} from '#packages/sdk/src/participant/worker/storage/database.js';

const databases: IDBDatabase[] = [];
const names: string[] = [];
const result = <Value>(request: IDBRequest<Value>) =>
    new Promise<Value>((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () =>
            reject(request.error ?? new Error('Cache fixture read failed.'));
    });
const write = (
    database: IDBDatabase,
    change: (store: IDBObjectStore) => void,
) =>
    new Promise<void>((resolve, reject) => {
        const transaction = database.transaction('aggregate', 'readwrite');
        transaction.oncomplete = () => resolve();
        transaction.onabort = () =>
            reject(
                transaction.error ?? new Error('Cache fixture write failed.'),
            );
        change(transaction.objectStore('aggregate'));
    });

// These are untrusted cache bytes and transport bounds only. No verifier,
// signature or verified setup capability is replaced by this fixture.
const fixture = async () => {
    const namespace = 'setup-cache-' + crypto.randomUUID();
    const name = namespacedName(setupCacheName, namespace);
    names.push(name);
    const opening = indexedDB.open(name, 1);
    opening.onupgradeneeded = () =>
        opening.result.createObjectStore('aggregate');
    const database = await result(opening);
    databases.push(database);
    const context = {
        namespace,
        module: { setup_chunk_capacity: () => 8 },
        profile: {
            setupContributorCount: 2,
            contribution: {
                // Three-byte coefficients make capacity six, not eight.
                polynomials: [{ expandedIndex: 7, bytes: 15, coefficients: 5 }],
            },
        },
    } as unknown as PublicProfileContext;
    await write(database, (store) => {
        for (const [offset, length] of [
            [0, 6],
            [6, 6],
            [12, 3],
        ])
            store.put(
                new Blob([
                    Uint8Array.from({ length }, (_, index) => offset + index),
                ]),
                [1, 7, offset],
            );
        store.put(new Blob([Uint8Array.of(99)]), [0, 7, 0]);
    });
    return { context, database };
};

afterEach(async () => {
    for (const database of databases.splice(0)) database.close();
    for (const name of names.splice(0))
        await result(indexedDB.deleteDatabase(name));
});

describe('bounded public aggregate cache reads', () => {
    it('delivers coefficient-aligned chunks in order, including the shorter final chunk', async () => {
        const { context } = await fixture();
        const seen: [number, number[]][] = [];
        await readFinalAggregate(context, 7, (offset, bytes) => {
            seen.push([offset, [...bytes]]);
        });
        expect(seen).toEqual([
            [0, [0, 1, 2, 3, 4, 5]],
            [6, [6, 7, 8, 9, 10, 11]],
            [12, [12, 13, 14]],
        ]);
    });

    it('does not read later chunks before the consumer has taken the current chunk', async () => {
        const { context, database } = await fixture();
        const seen: number[] = [];
        let changed: Promise<void> | undefined;
        await expect(
            readFinalAggregate(context, 7, (offset) => {
                seen.push(offset);
                if (offset === 0)
                    changed = write(database, (store) =>
                        store.delete([1, 7, 6]),
                    );
            }),
        ).rejects.toThrow('A cached aggregate chunk is missing.');
        await changed;
        expect(seen).toEqual([0]);
    });

    it('refuses missing, wrong-type and wrong-length chunks without delivering a later chunk', async () => {
        for (const invalid of [
            undefined,
            'bytes',
            new Blob([Uint8Array.of(6)]),
        ]) {
            const { context, database } = await fixture();
            await write(database, (store) => {
                if (invalid === undefined) store.delete([1, 7, 6]);
                else store.put(invalid, [1, 7, 6]);
            });
            const seen: number[] = [];
            await expect(
                readFinalAggregate(context, 7, (offset) => seen.push(offset)),
            ).rejects.toBeInstanceOf(PublicInputFailure);
            expect(seen).toEqual([0]);
        }
    });

    it('discards every cache generation when the owning consumer refuses a chunk', async () => {
        const { context, database } = await fixture();
        const refusal = new PublicInputFailure('The aggregate digest differs.');
        const seen: number[] = [];
        await expect(
            deliverFinalAggregate(context, () =>
                readFinalAggregate(context, 7, (offset) => {
                    seen.push(offset);
                    if (offset === 6) throw refusal;
                }),
            ),
        ).rejects.toBe(refusal);
        expect(seen).toEqual([0, 6]);
        const transaction = database.transaction('aggregate', 'readonly');
        expect(await result(transaction.objectStore('aggregate').count())).toBe(
            0,
        );
    });
});

// A stand-in for the module's ballot key commands: it records each call and
// answers as told. No key is verified here.
const withBallotModule = (
    context: PublicProfileContext,
    answer: (operation: number, offset: number) => number,
) => {
    const calls: number[][] = [];
    const module = {
        ...context.module,
        memory: new WebAssembly.Memory({ initial: 1 }),
        input_pointer: () => 0,
        input_capacity: () => 64,
        contribution_output_pointer: () => 0,
        contribution_output_length: () => 0,
        participant_ballot_command: (
            operation: number,
            offset: number,
            length: number,
        ) => {
            calls.push([operation, offset, length]);
            return answer(operation, offset);
        },
    };
    return {
        calls,
        context: { ...context, module } as unknown as PublicProfileContext,
    };
};
const cachedChunks = async (database: IDBDatabase) =>
    result(
        database
            .transaction('aggregate', 'readonly')
            .objectStore('aggregate')
            .count(),
    );

describe('ballot key delivery', () => {
    it('streams every cached chunk of the key and finishes it, keeping the cache', async () => {
        const fixed = await fixture();
        const { calls, context } = withBallotModule(fixed.context, () => 0);
        await deliverBallotKey(context, 7);
        expect(calls).toEqual([
            [2, 0, 6],
            [2, 6, 6],
            [2, 12, 3],
            [3, 0, 0],
        ]);
        expect(await cachedChunks(fixed.database)).toBe(4);
    });

    it('leaves a refused chunk or finish pending on public input and discards the cache', async () => {
        const refusals: ((operation: number, offset: number) => boolean)[] = [
            (operation, offset) => operation === 2 && offset === 6,
            (operation) => operation === 3,
        ];
        for (const refused of refusals) {
            const fixed = await fixture();
            const { context } = withBallotModule(
                fixed.context,
                (operation, offset) => (refused(operation, offset) ? 1 : 0),
            );
            await expect(deliverBallotKey(context, 7)).rejects.toThrow(
                new PublicInputFailure('A ballot key was refused.'),
            );
            expect(await cachedChunks(fixed.database)).toBe(0);
        }
    });

    it('keeps a module failure a module failure instead of public input, and discards the cache', async () => {
        const fixed = await fixture();
        const failure = new ModuleFailure('The participant module failed.');
        const { context } = withBallotModule(fixed.context, (operation) => {
            if (operation === 3) throw failure;
            return 0;
        });
        await expect(deliverBallotKey(context, 7)).rejects.toBe(failure);
        expect(await cachedChunks(fixed.database)).toBe(0);
    });
});
