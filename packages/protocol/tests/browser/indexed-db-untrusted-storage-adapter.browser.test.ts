import { afterEach, describe, expect, it } from 'vitest';

import {
    createRuntimeRecordAuthenticatedRepairProtection,
    createRuntimeRecordProtection,
    readRuntimeRecord,
    stageRuntimeRecordWrite,
} from '#packages/protocol/src/runtime/authenticated-runtime-record';
import {
    IndexedDbUntrustedStorageAdapter,
    openIndexedDbUntrustedStorageAdapter,
} from '#packages/protocol/src/runtime/indexed-db-untrusted-storage-adapter';
import { openUntrustedStorageTransactionStore } from '#packages/protocol/src/runtime/untrusted-storage-transaction-store';
import {
    generateRuntimeStorageRootKey,
    runtimeAuthorityContext,
} from '#packages/protocol/tests/support/runtime-storage-test-support';

const openedAdapters: IndexedDbUntrustedStorageAdapter[] = [];
const databaseNames = new Set<string>();

const createDatabaseName = (): string => {
    const randomBytes = new Uint8Array(16);
    crypto.getRandomValues(randomBytes);
    const suffix = Array.from(randomBytes, (byte) =>
        byte.toString(16).padStart(2, '0'),
    ).join('');

    return `sealed-lattice-indexed-db-test-${suffix}`;
};

const openAdapter = async (
    databaseName = createDatabaseName(),
): Promise<IndexedDbUntrustedStorageAdapter> => {
    databaseNames.add(databaseName);
    const adapter = await openIndexedDbUntrustedStorageAdapter({
        databaseName,
    });
    openedAdapters.push(adapter);

    return adapter;
};

const deleteDatabase = (databaseName: string): Promise<void> =>
    new Promise<void>((resolve, reject) => {
        const request = indexedDB.deleteDatabase(databaseName);
        request.addEventListener('success', () => resolve(), { once: true });
        request.addEventListener(
            'error',
            () =>
                reject(
                    request.error ??
                        new Error('IndexedDB test database deletion failed.'),
                ),
            { once: true },
        );
        request.addEventListener(
            'blocked',
            () =>
                reject(
                    new Error(
                        'IndexedDB test database deletion was blocked by a leaked connection.',
                    ),
                ),
            { once: true },
        );
    });

const upgradeDatabase = (
    databaseName: string,
    version: number,
): Promise<IDBDatabase> =>
    new Promise<IDBDatabase>((resolve, reject) => {
        const request = indexedDB.open(databaseName, version);
        request.addEventListener('success', () => resolve(request.result), {
            once: true,
        });
        request.addEventListener(
            'error',
            () =>
                reject(
                    request.error ??
                        new Error('IndexedDB test version upgrade failed.'),
                ),
            { once: true },
        );
    });

const readRawValue = (database: IDBDatabase, key: string): Promise<unknown> =>
    new Promise<unknown>((resolve, reject) => {
        const transaction = database.transaction('records', 'readonly');
        const request = transaction.objectStore('records').get(key);
        transaction.addEventListener(
            'complete',
            () => resolve(request.result),
            { once: true },
        );
        transaction.addEventListener(
            'abort',
            () =>
                reject(
                    transaction.error ??
                        new Error('IndexedDB raw test read aborted.'),
                ),
            { once: true },
        );
    });

afterEach(async () => {
    for (const adapter of openedAdapters.splice(0).reverse()) {
        await adapter.close();
    }
    for (const databaseName of databaseNames) {
        await deleteDatabase(databaseName);
    }
    databaseNames.clear();
});

describe('IndexedDB untrusted storage adapter', () => {
    it('reopens an authenticated runtime record under the same live root-key authority', async () => {
        const databaseName = createDatabaseName();
        const namespace = 'authenticated-runtime';
        const rootKey = await generateRuntimeStorageRootKey();
        const authorityContext = runtimeAuthorityContext();
        const repairProtection =
            createRuntimeRecordAuthenticatedRepairProtection({
                authorityContext,
                maximumRecordSealingCount: 32,
                namespace,
                rootKey,
            });
        const recordProtection = createRuntimeRecordProtection({
            authorityContext,
            maximumRecordSealingCount: 32,
            rootKey,
        });
        const limits = {
            maximumActiveTransactionCount: 2,
            maximumLeaseByteLength: 1_024,
            maximumLeaseCountPerTransaction: 2,
            maximumOwnedRecordCount: 16,
            maximumStoredValueByteLength: 16_384,
            maximumTransactionByteLength: 2_048,
            maximumTransactionLifetimeMilliseconds: 1_000,
        } as const;
        const createIdentifier = (() => {
            let identifier = 0;
            return (kind: 'lease' | 'transaction') => {
                identifier += 1;
                const kindByte = kind === 'transaction' ? '01' : '02';
                return `${kindByte}${identifier
                    .toString(16)
                    .padStart(62, '0')}`;
            };
        })();

        const firstAdapter = await openAdapter(databaseName);
        const firstStore = await openUntrustedStorageTransactionStore({
            adapter: firstAdapter,
            authenticatedRepairProtection: repairProtection,
            createIdentifier,
            limits,
            namespace,
        });
        const transaction = await firstStore.store.beginTransaction({
            lifetimeMilliseconds: 1_000,
        });
        await stageRuntimeRecordWrite({
            expectedCurrentSealedBytes: null,
            logicalRecordKey: 'checkpoint/source-root',
            operationDomain:
                'sealed-lattice/runtime/test-source-root-record/v1',
            plaintext: new Uint8Array([1, 2, 3, 4]),
            protection: recordProtection,
            transaction,
        });
        await transaction.commit();
        await firstAdapter.close();

        const secondAdapter = await openAdapter(databaseName);
        const secondStore = await openUntrustedStorageTransactionStore({
            adapter: secondAdapter,
            authenticatedRepairProtection: repairProtection,
            createIdentifier,
            limits,
            namespace,
        });
        const restored = await readRuntimeRecord({
            logicalRecordKey: 'checkpoint/source-root',
            operationDomain:
                'sealed-lattice/runtime/test-source-root-record/v1',
            protection: recordProtection,
            store: secondStore.store,
        });
        expect(restored?.plaintext).toEqual(new Uint8Array([1, 2, 3, 4]));
        restored?.plaintext.fill(0);
        restored?.sealedBytes.fill(0);
    });

    it('publishes multi-key writes and deletes in one atomic transaction', async () => {
        const adapter = await openAdapter();
        await adapter.write('record-a', new Uint8Array([1]));
        await adapter.write('record-b', new Uint8Array([2]));
        await adapter.write('record-c', new Uint8Array([3]));

        expect(
            await adapter.applyAtomicMutation({
                expectedValues: [
                    { key: 'record-a', value: new Uint8Array([1]) },
                    { key: 'record-b', value: new Uint8Array([2]) },
                    { key: 'record-d', value: undefined },
                ],
                writes: [
                    { key: 'record-a', value: new Uint8Array([10]) },
                    { key: 'record-d', value: new Uint8Array([40]) },
                ],
                deletes: ['record-b', 'record-c'],
            }),
        ).toBe(true);
        expect(await adapter.read('record-a')).toEqual(new Uint8Array([10]));
        expect(await adapter.read('record-b')).toBeUndefined();
        expect(await adapter.read('record-c')).toBeUndefined();
        expect(await adapter.read('record-d')).toEqual(new Uint8Array([40]));
    });

    it('aborts every queued change on conflict and rejects invalid mutations before commit', async () => {
        const adapter = await openAdapter();
        await adapter.write('stable', new Uint8Array([1]));
        await adapter.write('delete-target', new Uint8Array([2]));

        expect(
            await adapter.applyAtomicMutation({
                expectedValues: [{ key: 'stable', value: new Uint8Array([0]) }],
                writes: [
                    { key: 'stable', value: new Uint8Array([9]) },
                    { key: 'new-record', value: new Uint8Array([3]) },
                ],
                deletes: ['delete-target'],
            }),
        ).toBe(false);
        expect(await adapter.read('stable')).toEqual(new Uint8Array([1]));
        expect(await adapter.read('new-record')).toBeUndefined();
        expect(await adapter.read('delete-target')).toEqual(
            new Uint8Array([2]),
        );

        await expect(
            adapter.applyAtomicMutation({
                expectedValues: [],
                writes: [{ key: 'stable', value: new Uint8Array([4]) }],
                deletes: ['stable'],
            }),
        ).rejects.toMatchObject({
            code: 'InvalidMutation',
            name: 'IndexedDbUntrustedStorageAdapterError',
        });
        expect(await adapter.read('stable')).toEqual(new Uint8Array([1]));
    });

    it('atomically preserves every cleanup candidate when an index references one', async () => {
        const adapter = await openAdapter();
        const firstObjectKey = 'objects/first';
        const secondObjectKey = 'objects/second';
        await adapter.write(firstObjectKey, new Uint8Array([1]));
        await adapter.write(secondObjectKey, new Uint8Array([2]));
        await adapter.write(
            'indices/committed',
            new TextEncoder().encode(firstObjectKey),
        );

        await expect(
            adapter.deleteUnreferencedObjects({
                indexPrefix: 'indices/',
                objectKeys: [firstObjectKey, secondObjectKey],
            }),
        ).resolves.toBe(false);
        expect(await adapter.read(firstObjectKey)).toEqual(new Uint8Array([1]));
        expect(await adapter.read(secondObjectKey)).toEqual(
            new Uint8Array([2]),
        );

        await adapter.delete('indices/committed');
        await expect(
            adapter.deleteUnreferencedObjects({
                indexPrefix: 'indices/',
                objectKeys: [firstObjectKey, secondObjectKey],
            }),
        ).resolves.toBe(true);
        expect(await adapter.read(firstObjectKey)).toBeUndefined();
        expect(await adapter.read(secondObjectKey)).toBeUndefined();
    });

    it('awaits an aborted transaction when request creation throws synchronously', async () => {
        const adapter = await openAdapter();
        const synchronousFailure = new Error(
            'Injected synchronous IndexedDB request failure.',
        );
        const originalPutDescriptor = Object.getOwnPropertyDescriptor(
            IDBObjectStore.prototype,
            'put',
        );
        if (originalPutDescriptor === undefined) {
            throw new Error('IndexedDB put descriptor is unavailable.');
        }
        Object.defineProperty(IDBObjectStore.prototype, 'put', {
            configurable: true,
            value: () => {
                throw synchronousFailure;
            },
            writable: true,
        });
        try {
            await expect(
                adapter.write('synchronous-failure', new Uint8Array([1])),
            ).rejects.toMatchObject({
                code: 'TransactionFailed',
                failureCause: synchronousFailure,
                name: 'IndexedDbUntrustedStorageAdapterError',
            });
        } finally {
            Object.defineProperty(
                IDBObjectStore.prototype,
                'put',
                originalPutDescriptor,
            );
        }

        await adapter.write('after-synchronous-failure', new Uint8Array([2]));
        expect(await adapter.read('after-synchronous-failure')).toEqual(
            new Uint8Array([2]),
        );
    });

    it('observes aborted comparison transactions when cursor creation throws synchronously', async () => {
        const adapter = await openAdapter();
        const synchronousFailure = new Error(
            'Injected synchronous IndexedDB cursor failure.',
        );
        const originalOpenCursorDescriptor = Object.getOwnPropertyDescriptor(
            IDBObjectStore.prototype,
            'openCursor',
        );
        if (originalOpenCursorDescriptor === undefined) {
            throw new Error('IndexedDB openCursor descriptor is unavailable.');
        }
        Object.defineProperty(IDBObjectStore.prototype, 'openCursor', {
            configurable: true,
            value: () => {
                throw synchronousFailure;
            },
            writable: true,
        });
        try {
            await expect(
                adapter.applyAtomicMutation({
                    deletes: [],
                    expectedValues: [
                        { key: 'missing-record', value: undefined },
                    ],
                    writes: [
                        {
                            key: 'uncommitted-record',
                            value: new Uint8Array([1]),
                        },
                    ],
                }),
            ).rejects.toMatchObject({
                code: 'TransactionFailed',
                failureCause: synchronousFailure,
                name: 'IndexedDbUntrustedStorageAdapterError',
            });
        } finally {
            Object.defineProperty(
                IDBObjectStore.prototype,
                'openCursor',
                originalOpenCursorDescriptor,
            );
        }

        expect(await adapter.read('uncommitted-record')).toBeUndefined();
    });

    it('persists strict transactions across safe close and reopen', async () => {
        const databaseName = createDatabaseName();
        const firstAdapter = await openAdapter(databaseName);
        await firstAdapter.write('persistent', new Uint8Array([1, 2, 3]));
        await firstAdapter.close();
        await expect(firstAdapter.read('persistent')).rejects.toMatchObject({
            code: 'Closed',
            name: 'IndexedDbUntrustedStorageAdapterError',
        });

        const secondAdapter = await openAdapter(databaseName);
        expect(await secondAdapter.read('persistent')).toEqual(
            new Uint8Array([1, 2, 3]),
        );
        expect(
            await secondAdapter.applyAtomicMutation({
                expectedValues: [
                    {
                        key: 'persistent',
                        value: new Uint8Array([1, 2, 3]),
                    },
                ],
                writes: [
                    {
                        key: 'persistent',
                        value: new Uint8Array([4, 5, 6]),
                    },
                ],
                deletes: [],
            }),
        ).toBe(true);
        await secondAdapter.close();

        const thirdAdapter = await openAdapter(databaseName);
        expect(await thirdAdapter.read('persistent')).toEqual(
            new Uint8Array([4, 5, 6]),
        );
    });

    it('aborts an active mutation before closing for a database version change', async () => {
        const databaseName = createDatabaseName();
        const adapter = await openAdapter(databaseName);
        const expectedValues = Array.from({ length: 4_096 }, (_, keyIndex) => ({
            key: `versionchange-expected-${keyIndex
                .toString()
                .padStart(4, '0')}`,
            value: undefined,
        }));
        const mutation = adapter.applyAtomicMutation({
            expectedValues,
            writes: [
                {
                    key: 'versionchange-write',
                    value: new Uint8Array([1]),
                },
            ],
            deletes: [],
        });
        const upgradedDatabasePromise = upgradeDatabase(databaseName, 2);

        await expect(mutation).rejects.toMatchObject({
            code: 'TransactionFailed',
            name: 'IndexedDbUntrustedStorageAdapterError',
        });
        await adapter.close();
        const upgradedDatabase = await upgradedDatabasePromise;
        expect(
            await readRawValue(upgradedDatabase, 'versionchange-write'),
        ).toBeUndefined();
        upgradedDatabase.close();
    });
});
