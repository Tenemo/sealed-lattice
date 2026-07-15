import { afterEach, describe, expect, it } from 'vitest';

import type {
    BrowserActionStorageCustody,
    BrowserActionStorageRootBinding,
    UntrustedExpectedStorageRootCommitment,
} from '#packages/protocol/src/runtime/browser-action-storage-custody';
import { openBrowserActionStorageCustodyWorker } from '#packages/protocol/src/runtime/browser-action-storage-custody-worker-channel';
import { deriveWebLockStorageNamespaceName } from '#packages/protocol/src/runtime/web-lock-owned-untrusted-storage-transaction-store';
import { createTestBytes } from '#packages/protocol/tests/support/action-storage-custody-test-support';

const transactionLimits = {
    maximumActiveTransactionCount: 2,
    maximumLeaseByteLength: 64,
    maximumLeaseCountPerTransaction: 2,
    maximumOwnedRecordCount: 32,
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

const untrustedExpectedCommitment = (
    storageRootCommitment: Uint8Array,
): UntrustedExpectedStorageRootCommitment =>
    Object.freeze({ storageRootCommitment: storageRootCommitment.slice() });

type OpeningWorker = Readonly<{
    opening: Promise<BrowserActionStorageCustody>;
    worker: Worker;
}>;

const openedCustodies = new Set<BrowserActionStorageCustody>();
const openedWorkers = new Set<Worker>();
const databaseNames = new Set<string>();

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
    it('persists, reopens, recovers, and deletes custody state', async () => {
        const databaseName = createDatabaseName();
        const firstCustody = await openWorker({
            databaseName,
        });
        const initialSnapshot = await firstCustody.initialize();
        const commitment = untrustedExpectedCommitment(
            initialSnapshot.storageRootCommitment,
        );

        await closeCustody(firstCustody);

        const secondCustody = await openWorker({
            databaseName,
            knownStorageRootCommitment: commitment.storageRootCommitment,
        });
        expect(await secondCustody.currentSnapshot()).toEqual(initialSnapshot);
        const wrongCommitment = untrustedExpectedCommitment(
            commitment.storageRootCommitment,
        );
        wrongCommitment.storageRootCommitment[63] ^= 0x01;
        await expect(
            secondCustody.openIntoOwnedWorker({
                expectedSnapshot: initialSnapshot,
                untrustedExpectedCommitment: wrongCommitment,
            }),
        ).rejects.toMatchObject({ code: 'CommitmentMismatch' });
        await secondCustody.openIntoOwnedWorker({
            expectedSnapshot: initialSnapshot,
            untrustedExpectedCommitment: commitment,
        });
        const challenge = await secondCustody.beginRecoveryExport({
            expectedSnapshot: initialSnapshot,
            untrustedExpectedCommitment: commitment,
        });
        const confirmation = await secondCustody.confirmRecoveryExport({
            confirmedChecksum: challenge.recoveryChecksum,
            preparationIdentifier: challenge.preparationIdentifier,
        });
        expect(confirmation.canonicalRecoveryText).toHaveLength(708);
        expect(confirmation.snapshot.recoveryValueExported).toBe(true);

        const recoveredSnapshot = await secondCustody.recover({
            caseInsensitiveRecoveryText:
                confirmation.canonicalRecoveryText.toLowerCase(),
            untrustedExpectedCommitment: commitment,
            expectedSnapshot: confirmation.snapshot,
        });
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
                untrustedExpectedCommitment: commitment,
            }),
        ).rejects.toMatchObject({ code: 'Unavailable' });
    });

    it('transports authenticated local-record operations across the worker channel', async () => {
        const custody = await openWorker({
            databaseName: createDatabaseName(),
        });
        const snapshot = await custody.initialize();
        await custody.openIntoOwnedWorker({
            expectedSnapshot: snapshot,
            untrustedExpectedCommitment: untrustedExpectedCommitment(
                snapshot.storageRootCommitment,
            ),
        });
        const expectedContext = {
            actionRandomnessCommitment: createTestBytes(64, 101),
            creationRecoveryEpoch: 0n,
            identifierInput: {
                recordType: 'aggregateThresholdShare',
                recipientInputRoot: createTestBytes(64, 117),
            },
            recordVersion: 0n,
        } as const;
        const plaintext = createTestBytes(4_097, 133);
        const envelope = await custody.sealLocalRecord({
            ...expectedContext,
            plaintext,
        });

        await expect(
            custody.openLocalRecord({ ...expectedContext, envelope }),
        ).resolves.toEqual(plaintext);
        await expect(
            custody.hashLocalRecordEnvelope(envelope),
        ).resolves.toHaveLength(64);
        await expect(
            custody.openLocalRecord({
                ...expectedContext,
                creationRecoveryEpoch: 1n,
                envelope,
            }),
        ).rejects.toMatchObject({ code: 'OwnedWorkerFailure' });
        await expect(
            custody.sealLocalRecord({
                ...expectedContext,
                predecessorRecordHash: createTestBytes(64, 149),
                plaintext,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
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
                untrustedExpectedCommitment: untrustedExpectedCommitment(
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
        const commitment = untrustedExpectedCommitment(
            snapshot.storageRootCommitment,
        );
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
            untrustedExpectedCommitment: commitment,
        });
        const challenge = await secondCustody.beginRecoveryExport({
            expectedSnapshot: snapshot,
            untrustedExpectedCommitment: commitment,
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
});
