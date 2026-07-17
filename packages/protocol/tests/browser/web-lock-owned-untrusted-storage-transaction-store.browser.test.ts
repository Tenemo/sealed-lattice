import { afterEach, describe, expect, it } from 'vitest';

import type { UntrustedStorageAuthenticatedRepairProtection } from '#packages/protocol/src/runtime/untrusted-storage-transaction-store';
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
    maximumOwnedRecordCount: 32,
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
const repairProtections = new Map<
    string,
    UntrustedStorageAuthenticatedRepairProtection
>();

const copyToArrayBufferView = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => {
    const copy = new Uint8Array(new ArrayBuffer(bytes.byteLength));
    copy.set(bytes);
    return copy;
};

const repairProtectionFor = (
    databaseName: string,
): UntrustedStorageAuthenticatedRepairProtection => {
    const existingProtection = repairProtections.get(databaseName);
    if (existingProtection !== undefined) {
        return existingProtection;
    }
    const authenticationKey = crypto.subtle.generateKey(
        { length: 256, name: 'AES-GCM' },
        false,
        ['decrypt', 'encrypt'],
    );
    const repairIdentity = crypto.getRandomValues(new Uint8Array(64));
    const protection = Object.freeze({
        deriveDigest: async (bytes: Uint8Array) =>
            new Uint8Array(
                await crypto.subtle.digest(
                    'SHA-512',
                    copyToArrayBufferView(bytes),
                ),
            ),
        open: async (sealedBytes: Uint8Array) => {
            if (sealedBytes.byteLength < 28) {
                throw new Error('Test repair head is truncated.');
            }
            const nonce = copyToArrayBufferView(sealedBytes.slice(0, 12));
            const ciphertext = copyToArrayBufferView(sealedBytes.slice(12));
            return new Uint8Array(
                await crypto.subtle.decrypt(
                    { iv: nonce, name: 'AES-GCM' },
                    await authenticationKey,
                    ciphertext,
                ),
            );
        },
        repairIdentity,
        seal: async (plaintext: Uint8Array) => {
            const nonce = crypto.getRandomValues(new Uint8Array(12));
            const ciphertext = new Uint8Array(
                await crypto.subtle.encrypt(
                    { iv: nonce, name: 'AES-GCM' },
                    await authenticationKey,
                    copyToArrayBufferView(plaintext),
                ),
            );
            const sealedBytes = new Uint8Array(
                nonce.byteLength + ciphertext.byteLength,
            );
            sealedBytes.set(nonce);
            sealedBytes.set(ciphertext, nonce.byteLength);
            return sealedBytes;
        },
    });
    repairProtections.set(databaseName, protection);
    return protection;
};
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
    authenticatedRepairProtection: repairProtectionFor(databaseName),
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

const exclusiveLockIsAvailable = async (lockName: string): Promise<boolean> => {
    let lockWasAvailable: boolean | undefined;
    await navigator.locks.request(
        lockName,
        { ifAvailable: true, mode: 'exclusive' },
        (lock) => {
            lockWasAvailable = lock !== null;
        },
    );
    if (lockWasAvailable === undefined) {
        throw new Error('The Web Lock availability probe did not run.');
    }
    return lockWasAvailable;
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

        expect(await exclusiveLockIsAvailable(lockName)).toBe(false);
        expect(firstHandle.state()).toBe('open');

        await firstHandle.close();
        const secondHandle = await secondOpenRequest;
        expect(await exclusiveLockIsAvailable(lockName)).toBe(false);
        expect(secondHandle.state()).toBe('open');

        await secondHandle.close();
        const thirdHandle = await openOwnedStore(configuration);
        expect(thirdHandle.state()).toBe('open');
    });

    it('fails closed if another browser client steals the held lock', async () => {
        const databaseName = createDatabaseName();
        const configuration = configurationFor(databaseName);
        const lockName = deriveWebLockStorageNamespaceName(configuration);
        const handle = await openOwnedStore(configuration);
        const retainedStore = handle.store;
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
        releaseStolenLock?.();
        await stealingRequest;
        await expect(handle.close()).rejects.toMatchObject({
            code: 'LockCallbackExited',
            name: 'WebLockOwnedStorageError',
        });
        expect(handle.state()).toBe('failed');
        expect(() => handle.store).toThrowError(
            expect.objectContaining({
                code: 'Unavailable',
                name: 'WebLockOwnedStorageError',
            }),
        );
        await expect(
            retainedStore.beginTransaction({ lifetimeMilliseconds: 1_000 }),
        ).rejects.toMatchObject({
            code: 'Closed',
            name: 'IndexedDbUntrustedStorageAdapterError',
        });
    });

    it('runs abandoned-object repair only after the previous owner closes', async () => {
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
        expect(await exclusiveLockIsAvailable(lockName)).toBe(false);
        expect(firstHandle.state()).toBe('open');

        await firstHandle.close();
        const secondHandle = await secondOpenRequest;
        expect(secondHandle.repairReport).toMatchObject({
            removedCorruptIndexCount: 0,
            removedUnreferencedObjectCount: 1,
            retainedObjectCount: 0,
        });
    });
});
