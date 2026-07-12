import { afterEach, describe, expect, it } from 'vitest';

import {
    IndexedDbUntrustedStorageAdapter,
    openIndexedDbUntrustedStorageAdapter,
} from '#packages/protocol/src/runtime/indexed-db-untrusted-storage-adapter';
import { openUntrustedStorageTransactionStore } from '#packages/protocol/src/runtime/untrusted-storage-transaction-store';

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
    it('compares exact present and absent values before mutation', async () => {
        const adapter = await openAdapter();
        await adapter.write('present', new Uint8Array([1, 2, 3]));

        expect(
            await adapter.applyAtomicMutation({
                expectedValues: [
                    { key: 'present', value: new Uint8Array([1, 2, 3]) },
                    { key: 'absent', value: undefined },
                ],
                writes: [
                    { key: 'present', value: new Uint8Array([4, 5, 6]) },
                    { key: 'absent', value: new Uint8Array([7]) },
                ],
                deletes: [],
            }),
        ).toBe(true);
        expect(await adapter.read('present')).toEqual(
            new Uint8Array([4, 5, 6]),
        );
        expect(await adapter.read('absent')).toEqual(new Uint8Array([7]));

        expect(
            await adapter.applyAtomicMutation({
                expectedValues: [
                    { key: 'present', value: new Uint8Array([4, 5, 0]) },
                ],
                writes: [{ key: 'present', value: new Uint8Array([9, 9, 9]) }],
                deletes: [],
            }),
        ).toBe(false);
        expect(
            await adapter.applyAtomicMutation({
                expectedValues: [{ key: 'absent', value: undefined }],
                writes: [],
                deletes: ['present'],
            }),
        ).toBe(false);
        expect(await adapter.read('present')).toEqual(
            new Uint8Array([4, 5, 6]),
        );
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

    it('lists only the sorted string keys under the requested prefix', async () => {
        const adapter = await openAdapter();
        await adapter.write('other/01', new Uint8Array([1]));
        await adapter.write('prefix', new Uint8Array([2]));
        await adapter.write('prefix/02', new Uint8Array([3]));
        await adapter.write('prefix/a', new Uint8Array([4]));
        await adapter.write('prefix/01', new Uint8Array([5]));
        await adapter.write('prefix0/01', new Uint8Array([6]));

        expect(await adapter.listKeys('prefix/')).toEqual([
            'prefix/01',
            'prefix/02',
            'prefix/a',
        ]);
        expect(await adapter.listKeys('missing/')).toEqual([]);
    });

    it('copies caller and IndexedDB buffers across every operation boundary', async () => {
        const adapter = await openAdapter();
        const writeBytes = new Uint8Array([1, 2, 3]);
        const writePromise = adapter.write('copied', writeBytes);
        writeBytes.fill(9);
        await writePromise;

        const firstRead = await adapter.read('copied');
        expect(firstRead).toEqual(new Uint8Array([1, 2, 3]));
        firstRead?.fill(8);
        expect(await adapter.read('copied')).toEqual(new Uint8Array([1, 2, 3]));

        const expectedBytes = new Uint8Array([1, 2, 3]);
        const replacementBytes = new Uint8Array([4, 5, 6]);
        const mutationPromise = adapter.applyAtomicMutation({
            expectedValues: [{ key: 'copied', value: expectedBytes }],
            writes: [{ key: 'copied', value: replacementBytes }],
            deletes: [],
        });
        expectedBytes.fill(0);
        replacementBytes.fill(0);
        expect(await mutationPromise).toBe(true);
        expect(await adapter.read('copied')).toEqual(new Uint8Array([4, 5, 6]));
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

    it('persists committed transaction-store records and recovers abandoned leases after reopen', async () => {
        const databaseName = createDatabaseName();
        const firstAdapter = await openAdapter(databaseName);
        const firstOpen = await openUntrustedStorageTransactionStore({
            adapter: firstAdapter,
            limits: {
                maximumActiveTransactionCount: 2,
                maximumLeaseByteLength: 64,
                maximumLeaseCountPerTransaction: 2,
                maximumStoredValueByteLength: 4_096,
                maximumTransactionByteLength: 128,
                maximumTransactionLifetimeMilliseconds: 10_000,
            },
            monotonicClockMilliseconds: () => performance.now(),
            namespace: 'browser-integration',
        });
        const committedBytes = new Uint8Array([1, 2, 3]);
        const committedTransaction = await firstOpen.store.beginTransaction({
            lifetimeMilliseconds: 1_000,
        });
        const committedLease = await committedTransaction.issueWriteLease({
            declaredByteLength: committedBytes.byteLength,
            logicalRecordKey: 'committed',
        });
        await committedLease.write(committedBytes);
        await committedLease.seal(({ bytes, logicalRecordKey }) => {
            if (
                logicalRecordKey !== 'committed' ||
                bytes.byteLength !== committedBytes.byteLength ||
                !bytes.every((byte, byteIndex) =>
                    Object.is(byte, committedBytes[byteIndex]),
                )
            ) {
                throw new Error('committed record authentication failed');
            }
        });
        await committedTransaction.commit();

        const abandonedTransaction = await firstOpen.store.beginTransaction({
            lifetimeMilliseconds: 1_000,
        });
        const abandonedLease = await abandonedTransaction.issueWriteLease({
            declaredByteLength: 2,
            logicalRecordKey: 'abandoned',
        });
        await abandonedLease.write(new Uint8Array([9, 9]));
        await firstAdapter.close();

        const secondAdapter = await openAdapter(databaseName);
        const secondOpen = await openUntrustedStorageTransactionStore({
            adapter: secondAdapter,
            limits: {
                maximumActiveTransactionCount: 2,
                maximumLeaseByteLength: 64,
                maximumLeaseCountPerTransaction: 2,
                maximumStoredValueByteLength: 4_096,
                maximumTransactionByteLength: 128,
                maximumTransactionLifetimeMilliseconds: 10_000,
            },
            monotonicClockMilliseconds: () => performance.now(),
            namespace: 'browser-integration',
        });
        expect(secondOpen.recoveryReport).toMatchObject({
            removedCorruptIndexCount: 0,
            removedUnreferencedObjectCount: 1,
            retainedObjectCount: 1,
        });
        expect(
            await secondOpen.store.readAuthenticated({
                authenticate: ({ bytes, logicalRecordKey }) => {
                    if (
                        logicalRecordKey !== 'committed' ||
                        bytes.byteLength !== committedBytes.byteLength ||
                        !bytes.every((byte, byteIndex) =>
                            Object.is(byte, committedBytes[byteIndex]),
                        )
                    ) {
                        throw new Error(
                            'reopened record authentication failed',
                        );
                    }
                },
                logicalRecordKey: 'committed',
            }),
        ).toEqual(committedBytes);
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
