import type {
    BrowserActionStorageCustody,
    BrowserDeviceWrappingSnapshot,
} from '#packages/protocol/src/runtime/browser-action-storage-custody';
import {
    installBrowserActionStorageCustodyWorkerHost,
    type BrowserActionStorageCustodyWorkerConfiguration,
} from '#packages/protocol/src/runtime/browser-action-storage-custody-worker-channel';
import type {
    WebLockOwnedBrowserActionStorageCustody,
    WebLockOwnedStorageState,
} from '#packages/protocol/src/runtime/web-lock-owned-untrusted-storage-transaction-store';

const workerScope = globalThis as unknown as Readonly<{
    addEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void;
    postMessage(message: unknown): void;
    removeEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void;
}>;

const unavailableOperation = (): Promise<never> =>
    Promise.reject(
        new Error('The malicious-result fixture supports only initialize.'),
    );

const browserStorageFailure = (failure: unknown): Error =>
    failure instanceof Error
        ? failure
        : new Error('Malicious-result fixture storage operation failed.');

const openMaliciousCustody = async (
    configuration: BrowserActionStorageCustodyWorkerConfiguration,
): Promise<WebLockOwnedBrowserActionStorageCustody> => {
    let releaseHeldLock: (() => void) | undefined;
    const heldLockRelease = new Promise<void>((resolve) => {
        releaseHeldLock = resolve;
    });
    let reportLockAcquired: (() => void) | undefined;
    const lockAcquired = new Promise<void>((resolve) => {
        reportLockAcquired = resolve;
    });
    const lockName = `sealed-lattice-malicious-result-test-${configuration.databaseName}`;
    const lockCompletion = navigator.locks.request(
        lockName,
        { mode: 'exclusive' },
        async (lock) => {
            if (lock?.name !== lockName || lock.mode !== 'exclusive') {
                throw new Error(
                    'The malicious-result fixture lock was not granted.',
                );
            }
            reportLockAcquired?.();
            await heldLockRelease;
        },
    );

    const recordInitializeInvocation = (databaseName: string): Promise<void> =>
        new Promise<void>((resolve, reject) => {
            const request = indexedDB.open(`${databaseName}-invocations`, 1);
            request.addEventListener('upgradeneeded', () => {
                request.result.createObjectStore('records');
            });
            request.addEventListener(
                'error',
                () => reject(browserStorageFailure(request.error)),
                { once: true },
            );
            request.addEventListener(
                'success',
                () => {
                    const database = request.result;
                    const transaction = database.transaction(
                        'records',
                        'readwrite',
                    );
                    transaction.objectStore('records').put(true, 'initialize');
                    transaction.addEventListener(
                        'complete',
                        () => {
                            database.close();
                            resolve();
                        },
                        { once: true },
                    );
                    transaction.addEventListener(
                        'error',
                        () => {
                            database.close();
                            reject(browserStorageFailure(transaction.error));
                        },
                        { once: true },
                    );
                    transaction.addEventListener(
                        'abort',
                        () => {
                            database.close();
                            reject(browserStorageFailure(transaction.error));
                        },
                        { once: true },
                    );
                },
                { once: true },
            );
        });
    await lockAcquired;
    const generatedKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
    );
    if ('privateKey' in generatedKey) {
        throw new Error('Test WebCrypto returned a key pair for AES-GCM.');
    }
    let releaseCurrentSnapshot: (() => void) | undefined;
    let closePromise: Promise<void> | undefined;
    let state: WebLockOwnedStorageState = 'open';
    const custody: BrowserActionStorageCustody = {
        beginRecoveryExport: unavailableOperation,
        cancelRecoveryExport: unavailableOperation,
        close: () => Promise.resolve(),
        confirmRecoveryExport: unavailableOperation,
        currentSnapshot: () =>
            new Promise<undefined>((resolve) => {
                releaseCurrentSnapshot = () => resolve(undefined);
            }),
        delete: unavailableOperation,
        initialize: async () => {
            await recordInitializeInvocation(configuration.databaseName);

            return {
                deviceKey: generatedKey,
                mutationIdentifier: new Uint8Array(32),
                recoveryValueExported: false,
                wrappedStorageRoot: new Uint8Array(96),
            } as unknown as BrowserDeviceWrappingSnapshot;
        },
        openIntoOwnedWorker: unavailableOperation,
        recover: unavailableOperation,
    };

    return {
        close: () => {
            closePromise ??= (async () => {
                state = 'closing';
                releaseCurrentSnapshot?.();
                releaseHeldLock?.();
                await lockCompletion;
                state = 'closed';
            })();

            return closePromise;
        },
        custody,
        state: () => state,
    };
};

installBrowserActionStorageCustodyWorkerHost({
    openOwnedCustody: openMaliciousCustody,
    workerScope,
});
