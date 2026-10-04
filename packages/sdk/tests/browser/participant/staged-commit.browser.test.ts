import { afterEach, describe, expect, it, vi } from 'vitest';

import {
    readParticipantLimits,
    readParticipantProfile,
} from '#packages/sdk/src/participant/worker/bounds.js';
import type { ProfileContext } from '#packages/sdk/src/participant/worker/context.js';
import {
    custodyIdentity,
    custodyPurpose,
} from '#packages/sdk/src/participant/worker/identity.js';
import { instantiateParticipantKernel } from '#packages/sdk/src/participant/worker/kernel.js';
import { noParallelHelpers } from '#packages/sdk/src/participant/worker/parallel.js';
import type { ParticipantStoredRecord } from '#packages/sdk/src/participant/worker/predecessor.js';
import { sealRecord } from '#packages/sdk/src/participant/worker/records.js';
import {
    commitRoot,
    createRootKey,
    encodeManifest,
    openRoot,
    rootAssociatedData,
    sealRoot,
} from '#packages/sdk/src/participant/worker/root.js';
import type {
    AuthenticatedRoot,
    ParticipantManifest,
    RootTransition,
} from '#packages/sdk/src/participant/worker/root.js';
import {
    openParticipantDatabase,
    readParticipantValue,
    snapshotParticipant,
    StoragePending,
} from '#packages/sdk/src/participant/worker/storage.js';
import type { ParticipantStore } from '#packages/sdk/src/participant/worker/storage.js';

const module = await WebAssembly.compile(
    await (
        await fetch(new URL('../../../dist/participant.wasm', import.meta.url))
    ).arrayBuffer(),
);
const databases: IDBDatabase[] = [];
const hexadecimal = (bytes: Uint8Array) =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
const requestResult = <Value>(request: IDBRequest<Value>) =>
    new Promise<Value>((resolve, reject) => {
        request.onsuccess = () => resolve(request.result);
        request.onerror = () =>
            reject(request.error ?? new Error('Fixture read failed.'));
    });
const write = (
    database: IDBDatabase,
    stores: ParticipantStore[],
    change: (transaction: IDBTransaction) => void,
) =>
    new Promise<void>((resolve, reject) => {
        const transaction = database.transaction(stores, 'readwrite', {
            durability: 'strict',
        });
        transaction.oncomplete = () => resolve();
        transaction.onabort = () =>
            reject(transaction.error ?? new Error('Fixture write failed.'));
        change(transaction);
    });

// Transaction-layer custody fixture: real root and record AES-GCM, real
// module identities and real IndexedDB. Opaque suffix bytes stand for an
// original generation-six seed/checkpoint and its completed successor;
// they are not protocol capabilities or valid contribution proofs.
const fixture = async () => {
    const namespace = 'staged-' + crypto.randomUUID();
    const database = await openParticipantDatabase(namespace);
    databases.push(database);
    const { kernel, handlers } = await instantiateParticipantKernel(
        module,
        noParallelHelpers,
    );
    expect(kernel.worker_reserve(0, 0)).toBe(0);
    const limits = readParticipantLimits(kernel);
    const profile = readParticipantProfile(kernel, limits, 3, 2);
    if (profile === undefined)
        throw new Error('The fixture profile was refused.');
    const runtime = new Uint8Array(64).fill(29);
    const context: ProfileContext = {
        namespace,
        database,
        kernel,
        handlers,
        parallel: noParallelHelpers,
        runtime,
        limits,
        profile,
        position: 0,
        separateEvaluation: false,
    };
    const oldPlaintext = Uint8Array.of(7, 11, 19);
    const oldAssociatedData = Uint8Array.of(6, 0);
    const oldRecord = await sealRecord(oldAssociatedData, oldPlaintext);
    const newAssociatedData = Uint8Array.of(7, 0);
    const newRecord = await sealRecord(
        newAssociatedData,
        Uint8Array.of(23, 31),
    );
    const required: ParticipantStoredRecord = {
        store: 'checkpoint',
        key: 0,
        byteLength: oldRecord.ciphertext.length,
        encryption: { key: oldRecord.key, additionalData: oldAssociatedData },
    };
    const staged: ParticipantStoredRecord = {
        store: 'contribution',
        key: [1, 0],
        byteLength: newRecord.ciphertext.length,
        encryption: { key: newRecord.key, additionalData: newAssociatedData },
    };
    const manifest: ParticipantManifest = {
        dataKeys: new Uint8Array(96).fill(37),
        poll: new Uint8Array(64).fill(41),
        references: [],
        suffixes: {
            contribution: new Uint8Array([
                ...new Uint8Array(64).fill(43),
                ...oldRecord.key,
                ...oldAssociatedData,
            ]),
        },
    };
    const plaintext = encodeManifest(manifest, 6);
    const key = await createRootKey();
    const sealed = await sealRoot(
        key,
        6,
        rootAssociatedData(runtime),
        plaintext,
    );
    const head = {
        generation: 6,
        runtime: hexadecimal(runtime),
        hash: hexadecimal(custodyIdentity(kernel, custodyPurpose.root, sealed)),
    };
    const predecessor: AuthenticatedRoot = { head, plaintext, manifest };
    const successor: ParticipantManifest = {
        ...manifest,
        suffixes: { contribution: Uint8Array.of(83, 67, 66, 49) },
    };
    await write(
        database,
        ['head', 'root', 'key', 'checkpoint', 'contribution'],
        (transaction) => {
            transaction.objectStore('head').put(head, 0);
            transaction.objectStore('root').put(sealed, 0);
            transaction.objectStore('key').put(key, 0);
            transaction
                .objectStore('checkpoint')
                .add(new Blob([new Uint8Array(oldRecord.ciphertext)]), 0);
            transaction
                .objectStore('contribution')
                .add(new Blob([new Uint8Array(newRecord.ciphertext)]), [1, 0]);
        },
    );
    const transition = (): RootTransition => ({
        generation: 7,
        manifest: successor,
        predecessorRecords: [required],
        stagedRecords: [staged],
        write: (transaction) => transaction.objectStore('checkpoint').clear(),
    });
    const assertOriginal = async () => {
        const snapshot = await snapshotParticipant(database);
        expect(snapshot.head).toEqual(head);
        expect(snapshot.root).toEqual(sealed);
        expect(snapshot.counts.checkpoint).toBe(1);
        const reopened = await openRoot(
            snapshot.key as CryptoKey,
            6,
            rootAssociatedData(runtime),
            snapshot.root as Uint8Array,
        );
        expect(reopened).toEqual(plaintext);
        reopened.fill(0);
        const retained = await readParticipantValue(database, 'checkpoint', 0);
        if (!(retained instanceof Blob))
            throw new Error('Original checkpoint is missing.');
        expect(new Uint8Array(await retained.arrayBuffer())).toEqual(
            oldRecord.ciphertext,
        );
    };
    return {
        context,
        database,
        predecessor,
        transition,
        assertOriginal,
        newRecord,
        oldRecord,
    };
};

afterEach(async () => {
    vi.restoreAllMocks();
    for (const database of databases.splice(0)) {
        database.close();
        await requestResult(indexedDB.deleteDatabase(database.name));
    }
});

describe('staged-record root commit boundary', () => {
    it.each(['missing', 'corrupt'] as const)(
        'keeps intact original authority pending when an unreferenced new record is %s',
        async (damage) => {
            const fixed = await fixture();
            await write(fixed.database, ['contribution'], (transaction) => {
                const store = transaction.objectStore('contribution');
                if (damage === 'missing') store.delete([1, 0]);
                else {
                    const changed = fixed.newRecord.ciphertext.slice();
                    changed[changed.length - 1] ^= 1;
                    store.put(new Blob([changed]), [1, 0]);
                }
            });
            await fixed.assertOriginal();
            const failure = await commitRoot(
                fixed.context,
                fixed.predecessor,
                fixed.transition(),
            ).then(
                () => undefined,
                (error: unknown) => error,
            );
            await fixed.assertOriginal();
            expect(failure).toBeInstanceOf(StoragePending);
        },
    );

    it.each(['missing', 'corrupt'] as const)(
        'does not downgrade a %s original checkpoint to pending',
        async (damage) => {
            const fixed = await fixture();
            await write(fixed.database, ['checkpoint'], (transaction) => {
                const store = transaction.objectStore('checkpoint');
                if (damage === 'missing') store.delete(0);
                else {
                    const changed = fixed.oldRecord.ciphertext.slice();
                    changed[changed.length - 1] ^= 1;
                    store.put(new Blob([changed]), 0);
                }
            });
            let error: unknown;
            try {
                await commitRoot(
                    fixed.context,
                    fixed.predecessor,
                    fixed.transition(),
                );
            } catch (failure) {
                error = failure;
            }
            expect(error).toBeInstanceOf(Error);
            expect(error).not.toBeInstanceOf(StoragePending);
            expect((await snapshotParticipant(fixed.database)).head).toEqual(
                fixed.predecessor.head,
            );
        },
    );

    it('never treats a committed successor as the cached predecessor or deletes its new records', async () => {
        const fixed = await fixture();
        const successor = await commitRoot(
            fixed.context,
            fixed.predecessor,
            fixed.transition(),
        );
        expect(successor.head.generation).toBe(7);
        let error: unknown;
        try {
            await commitRoot(
                fixed.context,
                fixed.predecessor,
                fixed.transition(),
            );
        } catch (failure) {
            error = failure;
        }
        expect(error).toBeInstanceOf(Error);
        expect(error).not.toBeInstanceOf(StoragePending);
        const snapshot = await snapshotParticipant(fixed.database);
        expect(snapshot.head).toEqual(successor.head);
        expect(snapshot.counts.checkpoint).toBe(0);
        expect(snapshot.counts.contribution).toBe(1);
        const retained = await readParticipantValue(
            fixed.database,
            'contribution',
            [1, 0],
        );
        if (!(retained instanceof Blob))
            throw new Error('Committed output is missing.');
        expect(new Uint8Array(await retained.arrayBuffer())).toEqual(
            fixed.newRecord.ciphertext,
        );
    });

    it('does not classify an unexpected record as missing provisional output', async () => {
        const fixed = await fixture();
        await write(fixed.database, ['contribution'], (transaction) => {
            const store = transaction.objectStore('contribution');
            store.delete([1, 0]);
            store.add(
                new Blob([new Uint8Array(fixed.newRecord.ciphertext)]),
                [1, 77],
            );
        });
        const failure = await commitRoot(
            fixed.context,
            fixed.predecessor,
            fixed.transition(),
        ).then(
            () => undefined,
            (error: unknown) => error,
        );
        expect(failure).toBeInstanceOf(Error);
        expect(failure).not.toBeInstanceOf(StoragePending);
        await fixed.assertOriginal();
        expect(
            (await snapshotParticipant(fixed.database)).counts.contribution,
        ).toBe(1);
    });

    it('keeps an uncertain successful commit fatal when its readback fails', async () => {
        const fixed = await fixture();
        const transaction = fixed.database.transaction.bind(fixed.database);
        const failure = new Error('Successor readback is unavailable.');
        const intercepted = vi
            .spyOn(fixed.database, 'transaction')
            .mockImplementation((stores, mode, options) => {
                if (mode === 'readonly') throw failure;
                return transaction(stores, mode, options);
            });
        try {
            await expect(
                commitRoot(
                    fixed.context,
                    fixed.predecessor,
                    fixed.transition(),
                ),
            ).rejects.toBe(failure);
        } finally {
            intercepted.mockRestore();
        }
        const snapshot = await snapshotParticipant(fixed.database);
        expect(snapshot.head).toMatchObject({ generation: 7 });
        expect(snapshot.counts.checkpoint).toBe(0);
        expect(snapshot.counts.contribution).toBe(1);
    });
});
