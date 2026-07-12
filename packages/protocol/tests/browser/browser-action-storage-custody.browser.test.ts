import { afterEach, describe, expect, it } from 'vitest';

import type {
    BrowserActionStorageCustody,
    BrowserActionStorageRootBinding,
    ExternallyVerifiedStorageRootCommitment,
} from '#packages/protocol/src/runtime/browser-action-storage-custody';
import { openBrowserActionStorageCustodyWorker } from '#packages/protocol/src/runtime/browser-action-storage-custody-worker-channel';
import { deriveWebLockStorageNamespaceName } from '#packages/protocol/src/runtime/web-lock-owned-untrusted-storage-transaction-store';
import { createTestBytes } from '#packages/protocol/tests/support/action-storage-custody-test-support';

const transactionLimits = {
    maximumActiveTransactionCount: 2,
    maximumLeaseByteLength: 64,
    maximumLeaseCountPerTransaction: 2,
    maximumStoredValueByteLength: 4_096,
    maximumTransactionByteLength: 128,
    maximumTransactionLifetimeMilliseconds: 10_000,
} as const;
const testBinding: BrowserActionStorageRootBinding = Object.freeze({
    actionContextHash: createTestBytes(64, 41),
    ceremonyContextHash: createTestBytes(64, 23),
    participantId: createTestBytes(64, 59),
    suiteId: createTestBytes(64, 7),
});

const verifiedCommitment = (
    storageRootCommitment: Uint8Array,
): ExternallyVerifiedStorageRootCommitment =>
    Object.freeze({ storageRootCommitment: storageRootCommitment.slice() });

type OpeningWorker = Readonly<{
    opening: Promise<BrowserActionStorageCustody>;
    worker: Worker;
}>;

const openedCustodies = new Set<BrowserActionStorageCustody>();
const openedWorkers = new Set<Worker>();
const databaseNames = new Set<string>();

const browserStorageFailure = (failure: unknown): Error =>
    failure instanceof Error
        ? failure
        : new Error('Browser storage operation failed.');

const createDatabaseName = (): string => {
    const randomBytes = new Uint8Array(16);
    crypto.getRandomValues(randomBytes);
    const suffix = Array.from(randomBytes, (byte) =>
        byte.toString(16).padStart(2, '0'),
    ).join('');

    return `sealed-lattice-device-custody-test-${suffix}`;
};

const startOpeningWorker = (input: {
    binding?: BrowserActionStorageRootBinding;
    databaseName: string;
    knownStorageRootCommitment?: Uint8Array;
}): OpeningWorker => {
    const worker = new Worker(
        new URL(
            '../support/action-storage-custody-browser-worker.ts',
            import.meta.url,
        ),
        { type: 'module' },
    );
    openedWorkers.add(worker);
    databaseNames.add(input.databaseName);
    const opening = openBrowserActionStorageCustodyWorker({
        configuration: {
            acquisitionDeadlineEpochMilliseconds: undefined,
            binding: input.binding ?? testBinding,
            databaseName: input.databaseName,
            knownStorageRootCommitment: input.knownStorageRootCommitment,
            limits: transactionLimits,
            namespace: 'browser-custody',
        },
        worker,
    });
    void opening.then(
        (custody) => openedCustodies.add(custody),
        () => openedWorkers.delete(worker),
    );

    return { opening, worker };
};

const startOpeningMaliciousResultWorker = (input: {
    databaseName: string;
}): OpeningWorker => {
    const worker = new Worker(
        new URL(
            '../support/action-storage-custody-malicious-result-browser-worker.ts',
            import.meta.url,
        ),
        { type: 'module' },
    );
    openedWorkers.add(worker);
    databaseNames.add(input.databaseName);
    databaseNames.add(`${input.databaseName}-invocations`);
    const opening = openBrowserActionStorageCustodyWorker({
        configuration: {
            binding: testBinding,
            databaseName: input.databaseName,
            limits: transactionLimits,
            namespace: 'browser-custody',
        },
        worker,
    });
    void opening.then(
        (custody) => openedCustodies.add(custody),
        () => openedWorkers.delete(worker),
    );

    return { opening, worker };
};

const openWorker = async (input: {
    binding?: BrowserActionStorageRootBinding;
    databaseName: string;
    knownStorageRootCommitment?: Uint8Array;
}): Promise<BrowserActionStorageCustody> =>
    await startOpeningWorker(input).opening;

const closeCustody = async (
    custody: BrowserActionStorageCustody,
): Promise<void> => {
    try {
        await custody.close();
    } finally {
        openedCustodies.delete(custody);
    }
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
                        new Error(
                            'IndexedDB custody test database deletion failed.',
                        ),
                ),
            { once: true },
        );
        request.addEventListener(
            'blocked',
            () =>
                reject(
                    new Error(
                        'IndexedDB custody test database deletion was blocked by a leaked worker connection.',
                    ),
                ),
            { once: true },
        );
    });

const readInitializeInvocationMarker = (
    databaseName: string,
): Promise<boolean> =>
    new Promise<boolean>((resolve, reject) => {
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
                const transaction = database.transaction('records', 'readonly');
                const getRequest = transaction
                    .objectStore('records')
                    .get('initialize');
                getRequest.addEventListener(
                    'success',
                    () => {
                        database.close();
                        resolve(getRequest.result === true);
                    },
                    { once: true },
                );
                getRequest.addEventListener(
                    'error',
                    () => {
                        database.close();
                        reject(browserStorageFailure(getRequest.error));
                    },
                    { once: true },
                );
            },
            { once: true },
        );
    });

const assertNoCustodySecrets = (value: unknown): void => {
    if (value instanceof Uint8Array) {
        expect(value.byteLength).not.toBe(48);
        return;
    }
    if (Array.isArray(value)) {
        for (const entry of value) {
            assertNoCustodySecrets(entry);
        }
        return;
    }
    if (typeof value !== 'object' || value === null) {
        return;
    }
    const record = value as Record<string, unknown>;
    expect(Object.keys(record)).not.toContain('deviceKey');
    expect(Object.keys(record)).not.toContain('wrappedStorageRoot');
    expect(Object.keys(record)).not.toContain('actionStorageRoot');
    for (const entry of Object.values(record)) {
        assertNoCustodySecrets(entry);
    }
};

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
                `Custody Web Lock did not reach ${input.heldCount} held and ${input.pendingCount} pending requests.`,
            );
        }
        await new Promise<void>((resolve) => setTimeout(resolve, 5));
    }
};

afterEach(async () => {
    for (const custody of [...openedCustodies]) {
        try {
            await custody.close();
        } catch {
            // The worker is terminated below even if orderly close failed.
        }
    }
    openedCustodies.clear();
    for (const worker of openedWorkers) {
        worker.terminate();
    }
    openedWorkers.clear();
    for (const databaseName of databaseNames) {
        await deleteDatabase(databaseName);
    }
    databaseNames.clear();
});

describe('Browser action-storage custody worker channel', () => {
    it('persists, reopens, recovers, and deletes without crossing the worker secret boundary', async () => {
        const databaseName = createDatabaseName();
        const firstCustody = await openWorker({
            databaseName,
        });
        const initialSnapshot = await firstCustody.initialize();
        const commitment = verifiedCommitment(
            initialSnapshot.storageRootCommitment,
        );

        assertNoCustodySecrets(initialSnapshot);
        expect(Object.keys(firstCustody).sort()).toEqual([
            'beginRecoveryExport',
            'cancelRecoveryExport',
            'close',
            'confirmRecoveryExport',
            'currentSnapshot',
            'delete',
            'initialize',
            'openIntoOwnedWorker',
            'recover',
        ]);
        await closeCustody(firstCustody);

        const secondCustody = await openWorker({
            databaseName,
            knownStorageRootCommitment: commitment.storageRootCommitment,
        });
        expect(await secondCustody.currentSnapshot()).toEqual(initialSnapshot);
        const wrongCommitment = verifiedCommitment(
            commitment.storageRootCommitment,
        );
        wrongCommitment.storageRootCommitment[63] ^= 0x01;
        await expect(
            secondCustody.openIntoOwnedWorker({
                expectedSnapshot: initialSnapshot,
                externallyVerifiedCommitment: wrongCommitment,
            }),
        ).rejects.toMatchObject({ code: 'CommitmentMismatch' });
        await secondCustody.openIntoOwnedWorker({
            expectedSnapshot: initialSnapshot,
            externallyVerifiedCommitment: commitment,
        });
        const challenge = await secondCustody.beginRecoveryExport({
            expectedSnapshot: initialSnapshot,
            externallyVerifiedCommitment: commitment,
        });
        assertNoCustodySecrets(challenge);
        expect('canonicalRecoveryText' in challenge).toBe(false);
        const confirmation = await secondCustody.confirmRecoveryExport({
            confirmedChecksum: challenge.recoveryChecksum,
            preparationIdentifier: challenge.preparationIdentifier,
        });
        expect(confirmation.canonicalRecoveryText).toHaveLength(708);
        expect(confirmation.snapshot.recoveryValueExported).toBe(true);

        const recoveredSnapshot = await secondCustody.recover({
            caseInsensitiveRecoveryText:
                confirmation.canonicalRecoveryText.toLowerCase(),
            externallyVerifiedCommitment: commitment,
            expectedSnapshot: confirmation.snapshot,
        });
        assertNoCustodySecrets(recoveredSnapshot);
        expect(recoveredSnapshot.mutationIdentifier).not.toEqual(
            confirmation.snapshot.mutationIdentifier,
        );
        await expect(
            secondCustody.delete(initialSnapshot),
        ).rejects.toMatchObject({ code: 'Conflict' });
        await secondCustody.delete(recoveredSnapshot);
        expect(await secondCustody.currentSnapshot()).toBeUndefined();
        await expect(secondCustody.initialize()).rejects.toMatchObject({
            code: 'CommitmentRequired',
        });
        await expect(
            secondCustody.openIntoOwnedWorker({
                expectedSnapshot: recoveredSnapshot,
                externallyVerifiedCommitment: commitment,
            }),
        ).rejects.toMatchObject({ code: 'Unavailable' });
    });

    it('isolates persisted wrapping state by the complete action binding', async () => {
        const databaseName = createDatabaseName();
        const originalCustody = await openWorker({ databaseName });
        const originalSnapshot = await originalCustody.initialize();
        await closeCustody(originalCustody);

        const wrongBindingCustody = await openWorker({
            binding: Object.freeze({
                ...testBinding,
                participantId: createTestBytes(64, 181),
            }),
            databaseName,
            knownStorageRootCommitment: originalSnapshot.storageRootCommitment,
        });
        expect(await wrongBindingCustody.currentSnapshot()).toBeUndefined();
        await expect(wrongBindingCustody.initialize()).rejects.toMatchObject({
            code: 'CommitmentRequired',
        });
        await expect(
            wrongBindingCustody.openIntoOwnedWorker({
                expectedSnapshot: originalSnapshot,
                externallyVerifiedCommitment: verifiedCommitment(
                    originalSnapshot.storageRootCommitment,
                ),
            }),
        ).rejects.toMatchObject({ code: 'Unavailable' });
        await closeCustody(wrongBindingCustody);

        const exactBindingCustody = await openWorker({
            databaseName,
            knownStorageRootCommitment: originalSnapshot.storageRootCommitment,
        });
        expect(await exactBindingCustody.currentSnapshot()).toEqual(
            originalSnapshot,
        );
    });

    it('holds one cross-document Web Lock across the production worker channel', async () => {
        const databaseName = createDatabaseName();
        const firstCustody = await openWorker({
            databaseName,
        });
        const snapshot = await firstCustody.initialize();
        const commitment = verifiedCommitment(snapshot.storageRootCommitment);
        const secondOpening = startOpeningWorker({
            databaseName,
            knownStorageRootCommitment: commitment.storageRootCommitment,
        });
        const lockName = deriveWebLockStorageNamespaceName({
            databaseName,
            namespace: 'browser-custody',
        });

        await waitForLockCounts({
            heldCount: 1,
            lockName,
            pendingCount: 1,
        });
        await closeCustody(firstCustody);
        const secondCustody = await secondOpening.opening;
        await waitForLockCounts({
            heldCount: 1,
            lockName,
            pendingCount: 0,
        });
        expect(await secondCustody.currentSnapshot()).toEqual(snapshot);
        await secondCustody.openIntoOwnedWorker({
            expectedSnapshot: snapshot,
            externallyVerifiedCommitment: commitment,
        });
        const challenge = await secondCustody.beginRecoveryExport({
            expectedSnapshot: snapshot,
            externallyVerifiedCommitment: commitment,
        });
        expect(challenge.recoveryChecksum).toHaveLength(16);
        await secondCustody.cancelRecoveryExport(
            challenge.preparationIdentifier,
        );
        expect(await secondCustody.currentSnapshot()).toEqual(snapshot);
    });

    it('fails closed, destroys custody, and retains the terminal error after an unidentified request', async () => {
        const databaseName = createDatabaseName();
        const opening = startOpeningWorker({
            databaseName,
        });
        const custody = await opening.opening;
        await custody.initialize();
        const lockName = deriveWebLockStorageNamespaceName({
            databaseName,
            namespace: 'browser-custody',
        });

        opening.worker.postMessage({ malformedRequest: true });
        let firstFailure: unknown;
        try {
            await custody.currentSnapshot();
        } catch (error) {
            firstFailure = error;
        }
        expect(firstFailure).toMatchObject({
            code: 'OwnedWorkerFailure',
            name: 'BrowserActionStorageCustodyError',
        });
        let repeatedFailure: unknown;
        try {
            await custody.currentSnapshot();
        } catch (error) {
            repeatedFailure = error;
        }
        expect(repeatedFailure).toBe(firstFailure);
        await waitForLockCounts({
            heldCount: 0,
            lockName,
            pendingCount: 0,
        });
    });

    it('fails closed on a duplicate request identifier', async () => {
        const databaseName = createDatabaseName();
        const opening = startOpeningWorker({
            databaseName,
        });
        const custody = await opening.opening;
        await custody.initialize();
        const lockName = deriveWebLockStorageNamespaceName({
            databaseName,
            namespace: 'browser-custody',
        });

        opening.worker.postMessage({
            command: 'current-snapshot',
            input: undefined,
            messageKind: 'browser-action-storage-custody-request',
            requestIdentifier: 2,
        });

        await expect(custody.currentSnapshot()).rejects.toMatchObject({
            code: 'OwnedWorkerFailure',
            name: 'BrowserActionStorageCustodyError',
        });
        await waitForLockCounts({
            heldCount: 0,
            lockName,
            pendingCount: 0,
        });
    });

    it('validates host output before posting and closes custody when output contains secrets', async () => {
        const databaseName = createDatabaseName();
        const opening = startOpeningMaliciousResultWorker({
            databaseName,
        });
        const observedWorkerMessages: unknown[] = [];
        opening.worker.addEventListener('message', (event) => {
            observedWorkerMessages.push(event.data as unknown);
        });
        const custody = await opening.opening;
        const fixtureLockName = `sealed-lattice-malicious-result-test-${databaseName}`;
        await waitForLockCounts({
            heldCount: 1,
            lockName: fixtureLockName,
            pendingCount: 0,
        });

        let terminalFailure: unknown;
        try {
            await custody.initialize();
        } catch (error) {
            terminalFailure = error;
        }
        expect(terminalFailure).toMatchObject({
            code: 'OwnedWorkerFailure',
            name: 'BrowserActionStorageCustodyError',
        });
        for (const message of observedWorkerMessages) {
            assertNoCustodySecrets(message);
        }
        await waitForLockCounts({
            heldCount: 0,
            lockName: fixtureLockName,
            pendingCount: 0,
        });
        let repeatedFailure: unknown;
        try {
            await custody.currentSnapshot();
        } catch (error) {
            repeatedFailure = error;
        }
        expect(repeatedFailure).toBe(terminalFailure);
    });

    it('does not execute requests queued before terminal failure cleanup begins', async () => {
        const databaseName = createDatabaseName();
        const opening = startOpeningMaliciousResultWorker({
            databaseName,
        });
        const custody = await opening.opening;
        opening.worker.postMessage({
            command: 'current-snapshot',
            input: undefined,
            messageKind: 'browser-action-storage-custody-request',
            requestIdentifier: 2,
        });
        opening.worker.postMessage({
            command: 'initialize',
            input: undefined,
            messageKind: 'browser-action-storage-custody-request',
            requestIdentifier: 3,
        });
        opening.worker.postMessage({ malformedRequest: true });

        await expect(custody.currentSnapshot()).rejects.toMatchObject({
            code: 'OwnedWorkerFailure',
            name: 'BrowserActionStorageCustodyError',
        });
        expect(await readInitializeInvocationMarker(databaseName)).toBe(false);
    });
});
