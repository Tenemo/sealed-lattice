import { afterEach, describe, expect, it } from 'vitest';

import { openIndexedDbUntrustedStorageAdapter } from '#packages/protocol/src/runtime/indexed-db-untrusted-storage-adapter';
import {
    deriveWebLockStorageNamespaceName,
    openWebLockOwnedStorageTransactionStore,
    type WebLockOwnedStorageConfiguration,
    type WebLockOwnedStorageTransactionStore,
} from '#packages/protocol/src/runtime/web-lock-owned-untrusted-storage-transaction-store';
import { webLocksAvailable } from '#tests/support/browser-capabilities';

const transactionLimits = {
    maximumActiveTransactionCount: 2,
    maximumLeaseByteLength: 64,
    maximumLeaseCountPerTransaction: 2,
    maximumStoredValueByteLength: 4_096,
    maximumTransactionByteLength: 128,
    maximumTransactionLifetimeMilliseconds: 10_000,
} as const;

const openedHandles: WebLockOwnedStorageTransactionStore[] = [];
const pendingOpenRequests = new Set<
    Promise<WebLockOwnedStorageTransactionStore>
>();
const databaseNames = new Set<string>();
const openedFrames: HTMLIFrameElement[] = [];
const createDatabaseName = (): string => {
    const randomBytes = new Uint8Array(16);
    crypto.getRandomValues(randomBytes);
    const suffix = Array.from(randomBytes, (byte) =>
        byte.toString(16).padStart(2, '0'),
    ).join('');

    return `sealed-lattice-owned-storage-test-${suffix}`;
};

const configurationFor = (
    databaseName: string,
    overrides: Partial<WebLockOwnedStorageConfiguration> = {},
): WebLockOwnedStorageConfiguration => ({
    databaseName,
    limits: transactionLimits,
    namespace: 'browser-integration',
    ...overrides,
});

const openOwnedStore = (
    configuration: WebLockOwnedStorageConfiguration,
): Promise<WebLockOwnedStorageTransactionStore> => {
    databaseNames.add(configuration.databaseName);
    const openRequest = openWebLockOwnedStorageTransactionStore(configuration);
    pendingOpenRequests.add(openRequest);
    void openRequest.then(
        (handle) => {
            openedHandles.push(handle);
            pendingOpenRequests.delete(openRequest);
        },
        () => {
            pendingOpenRequests.delete(openRequest);
        },
    );

    return openRequest;
};

const createSeparateDocumentStorageProviders = async (): Promise<
    Pick<WebLockOwnedStorageConfiguration, 'indexedDbFactory' | 'lockManager'>
> => {
    const frame = document.createElement('iframe');
    const loaded = new Promise<void>((resolve) => {
        frame.addEventListener('load', () => resolve(), { once: true });
    });
    frame.srcdoc = '<!doctype html><title>Storage contender</title>';
    document.body.append(frame);
    openedFrames.push(frame);
    await loaded;
    const frameWindow = frame.contentWindow;
    if (
        frameWindow?.indexedDB === undefined ||
        typeof frameWindow.navigator.locks?.request !== 'function'
    ) {
        throw new Error(
            'The same-origin contender document lacks required browser storage APIs.',
        );
    }

    return {
        indexedDbFactory: frameWindow.indexedDB,
        lockManager: frameWindow.navigator.locks,
    };
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

const waitForLockCounts = async (input: {
    heldCount: number;
    lockName: string;
    pendingCount: number;
}): Promise<void> => {
    const deadlineMilliseconds = performance.now() + 2_000;
    while (true) {
        const snapshot = await navigator.locks.query();
        const heldCount = snapshot.held?.filter(
            (lock) => lock.name === input.lockName,
        ).length;
        const pendingCount = snapshot.pending?.filter(
            (lock) => lock.name === input.lockName,
        ).length;
        if (
            heldCount === input.heldCount &&
            pendingCount === input.pendingCount
        ) {
            return;
        }
        if (performance.now() >= deadlineMilliseconds) {
            throw new Error(
                `Web Lock state did not reach ${input.heldCount} held and ${input.pendingCount} pending requests.`,
            );
        }
        await new Promise<void>((resolve) => setTimeout(resolve, 5));
    }
};

const waitForHandleState = async (
    handle: WebLockOwnedStorageTransactionStore,
    expectedState: ReturnType<WebLockOwnedStorageTransactionStore['state']>,
): Promise<void> => {
    const deadlineMilliseconds = performance.now() + 2_000;
    while (handle.state() !== expectedState) {
        if (performance.now() >= deadlineMilliseconds) {
            throw new Error(
                `Owned storage state did not reach ${expectedState}.`,
            );
        }
        await new Promise<void>((resolve) => setTimeout(resolve, 5));
    }
};

afterEach(async () => {
    while (openedHandles.length > 0 || pendingOpenRequests.size > 0) {
        for (const handle of openedHandles.splice(0).reverse()) {
            try {
                await handle.close();
            } catch {
                // A failed ownership handle is already closed by the factory.
            }
        }
        await Promise.allSettled([...pendingOpenRequests]);
    }
    for (const frame of openedFrames.splice(0)) {
        frame.remove();
    }
    for (const databaseName of databaseNames) {
        await deleteDatabase(databaseName);
    }
    databaseNames.clear();
});

describe('Web Lock storage ownership configuration', () => {
    it('derives deterministic bounded names scoped by database and namespace', () => {
        const input = {
            databaseName: 'browser-storage',
            namespace: 'collective-setup',
        };
        const lockName = deriveWebLockStorageNamespaceName(input);

        expect(deriveWebLockStorageNamespaceName(input)).toBe(lockName);
        expect(
            deriveWebLockStorageNamespaceName({
                ...input,
                namespace: 'target-decryption',
            }),
        ).not.toBe(lockName);
        expect(
            deriveWebLockStorageNamespaceName({
                ...input,
                databaseName: 'other-browser-storage',
            }),
        ).not.toBe(lockName);
        expect(lockName.startsWith('-')).toBe(false);
        expect(lockName.length).toBeLessThanOrEqual(674);
    });

    it('fails closed when no Web Lock manager is available', async () => {
        const databaseName = createDatabaseName();

        await expect(
            openOwnedStore(
                configurationFor(databaseName, { lockManager: null }),
            ),
        ).rejects.toMatchObject({
            code: 'Unavailable',
            name: 'WebLockOwnedStorageError',
        });
    });
});

describe.skipIf(webLocksAvailable)(
    'Browser without Web Locks storage ownership',
    () => {
        it('fails closed with the browser implementation absent', async () => {
            const databaseName = createDatabaseName();

            await expect(
                openOwnedStore(configurationFor(databaseName)),
            ).rejects.toMatchObject({
                code: 'Unavailable',
                name: 'WebLockOwnedStorageError',
            });
        });
    },
);

describe.skipIf(!webLocksAvailable)('Web Lock storage ownership', () => {
    it('excludes a contender until close and permits orderly reacquisition', async () => {
        const databaseName = createDatabaseName();
        const configuration = configurationFor(databaseName);
        const lockName = deriveWebLockStorageNamespaceName(configuration);
        const firstHandle = await openOwnedStore(configuration);
        const separateDocumentProviders =
            await createSeparateDocumentStorageProviders();
        const secondOpenRequest = openOwnedStore(
            configurationFor(databaseName, separateDocumentProviders),
        );

        await waitForLockCounts({
            heldCount: 1,
            lockName,
            pendingCount: 1,
        });
        expect(firstHandle.state()).toBe('open');

        await firstHandle.close();
        const secondHandle = await secondOpenRequest;
        await waitForLockCounts({
            heldCount: 1,
            lockName,
            pendingCount: 0,
        });
        expect(secondHandle.state()).toBe('open');

        await secondHandle.close();
        const thirdHandle = await openOwnedStore(configuration);
        expect(thirdHandle.state()).toBe('open');
    });

    it('removes a cancelled queued request without releasing the owner', async () => {
        const databaseName = createDatabaseName();
        const configuration = configurationFor(databaseName);
        const lockName = deriveWebLockStorageNamespaceName(configuration);
        const firstHandle = await openOwnedStore(configuration);
        const cancellation = new AbortController();
        const queuedOpenRequest = openOwnedStore(
            configurationFor(databaseName, {
                acquisitionSignal: cancellation.signal,
            }),
        );

        await waitForLockCounts({
            heldCount: 1,
            lockName,
            pendingCount: 1,
        });
        cancellation.abort(new Error('test cancellation'));
        await expect(queuedOpenRequest).rejects.toMatchObject({
            code: 'AcquisitionCancelled',
            name: 'WebLockOwnedStorageError',
        });
        await waitForLockCounts({
            heldCount: 1,
            lockName,
            pendingCount: 0,
        });
        expect(firstHandle.state()).toBe('open');

        await firstHandle.close();
        const reacquiredHandle = await openOwnedStore(configuration);
        expect(reacquiredHandle.state()).toBe('open');
    });

    it('removes a queued request when its acquisition deadline expires', async () => {
        const databaseName = createDatabaseName();
        const configuration = configurationFor(databaseName);
        const lockName = deriveWebLockStorageNamespaceName(configuration);
        const firstHandle = await openOwnedStore(configuration);
        const queuedOpenRequest = openOwnedStore(
            configurationFor(databaseName, {
                acquisitionDeadlineEpochMilliseconds: Date.now() + 500,
            }),
        );

        await waitForLockCounts({
            heldCount: 1,
            lockName,
            pendingCount: 1,
        });
        await expect(queuedOpenRequest).rejects.toMatchObject({
            code: 'AcquisitionDeadlineExceeded',
            name: 'WebLockOwnedStorageError',
        });
        await waitForLockCounts({
            heldCount: 1,
            lockName,
            pendingCount: 0,
        });
        expect(firstHandle.state()).toBe('open');
    });

    it('closes the adapter before releasing ownership and refuses later operations', async () => {
        const databaseName = createDatabaseName();
        const handle = await openOwnedStore(configurationFor(databaseName));

        await handle.close();
        await handle.close();

        expect(handle.state()).toBe('closed');
        await expect(
            handle.store.beginTransaction({ lifetimeMilliseconds: 1_000 }),
        ).rejects.toMatchObject({
            code: 'Closed',
            name: 'IndexedDbUntrustedStorageAdapterError',
        });
    });

    it('fails closed if another browser client steals the held lock', async () => {
        const databaseName = createDatabaseName();
        const configuration = configurationFor(databaseName);
        const lockName = deriveWebLockStorageNamespaceName(configuration);
        const handle = await openOwnedStore(configuration);
        let releaseStolenLock: (() => void) | undefined;
        const stolenLockRelease = new Promise<void>((resolve) => {
            releaseStolenLock = resolve;
        });
        let reportStolenLockAcquired: (() => void) | undefined;
        const stolenLockAcquired = new Promise<void>((resolve) => {
            reportStolenLockAcquired = resolve;
        });

        const stealingRequest = navigator.locks.request(
            lockName,
            { mode: 'exclusive', steal: true },
            async (lock) => {
                if (lock?.name !== lockName) {
                    throw new Error(
                        'The hostile lock request was not granted.',
                    );
                }
                reportStolenLockAcquired?.();
                await stolenLockRelease;
            },
        );
        await stolenLockAcquired;
        await waitForHandleState(handle, 'failed');

        await expect(
            handle.store.beginTransaction({ lifetimeMilliseconds: 1_000 }),
        ).rejects.toMatchObject({
            code: 'Closed',
            name: 'IndexedDbUntrustedStorageAdapterError',
        });
        releaseStolenLock?.();
        await stealingRequest;
        await expect(handle.close()).rejects.toMatchObject({
            code: 'LockCallbackExited',
            name: 'WebLockOwnedStorageError',
        });
    });

    it('aborts opening and recovery if ownership is stolen before publication', async () => {
        const databaseName = createDatabaseName();
        databaseNames.add(databaseName);
        const configuration = configurationFor(databaseName);
        const lockName = deriveWebLockStorageNamespaceName(configuration);
        const seedAdapter = await openIndexedDbUntrustedStorageAdapter({
            databaseName,
        });
        const orphanWrites = Array.from({ length: 64 }, (_, recordIndex) => ({
            key: `sealed-lattice-runtime-store/browser-integration/objects/seed/lease-${recordIndex
                .toString()
                .padStart(2, '0')}`,
            value: new Uint8Array([recordIndex]),
        }));
        expect(
            await seedAdapter.applyAtomicMutation({
                deletes: [],
                expectedValues: orphanWrites.map(({ key }) => ({
                    key,
                    value: undefined,
                })),
                writes: orphanWrites,
            }),
        ).toBe(true);
        await seedAdapter.close();

        let openingSettled = false;
        const openingRequest = openOwnedStore(configuration);
        void openingRequest.then(
            () => {
                openingSettled = true;
            },
            () => {
                openingSettled = true;
            },
        );
        await waitForLockCounts({
            heldCount: 1,
            lockName,
            pendingCount: 0,
        });
        expect(openingSettled).toBe(false);

        let releaseStolenLock: (() => void) | undefined;
        const stolenLockRelease = new Promise<void>((resolve) => {
            releaseStolenLock = resolve;
        });
        let reportStolenLockAcquired: (() => void) | undefined;
        const stolenLockAcquired = new Promise<void>((resolve) => {
            reportStolenLockAcquired = resolve;
        });
        const stealingRequest = navigator.locks.request(
            lockName,
            { mode: 'exclusive', steal: true },
            async () => {
                reportStolenLockAcquired?.();
                await stolenLockRelease;
            },
        );

        await stolenLockAcquired;
        await expect(openingRequest).rejects.toMatchObject({
            code: 'LockCallbackExited',
            name: 'WebLockOwnedStorageError',
        });
        releaseStolenLock?.();
        await stealingRequest;

        const recoveredHandle = await openOwnedStore(configuration);
        expect(recoveredHandle.state()).toBe('open');
    });

    it('runs abandoned-object recovery only after the previous owner closes', async () => {
        const databaseName = createDatabaseName();
        const configuration = configurationFor(databaseName);
        const lockName = deriveWebLockStorageNamespaceName(configuration);
        const firstHandle = await openOwnedStore(configuration);
        const abandonedTransaction = await firstHandle.store.beginTransaction({
            lifetimeMilliseconds: 1_000,
        });
        const abandonedLease = await abandonedTransaction.issueWriteLease({
            declaredByteLength: 3,
            logicalRecordKey: 'abandoned-record',
        });
        await abandonedLease.write(new Uint8Array([7, 8, 9]));

        const separateDocumentProviders =
            await createSeparateDocumentStorageProviders();
        const secondOpenRequest = openOwnedStore(
            configurationFor(databaseName, separateDocumentProviders),
        );
        await waitForLockCounts({
            heldCount: 1,
            lockName,
            pendingCount: 1,
        });
        expect(firstHandle.state()).toBe('open');

        await firstHandle.close();
        const secondHandle = await secondOpenRequest;
        expect(secondHandle.recoveryReport).toMatchObject({
            removedCorruptIndexCount: 0,
            removedUnreferencedObjectCount: 1,
            retainedObjectCount: 0,
        });
    });
});
