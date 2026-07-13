import { afterEach, describe, expect, it } from 'vitest';

import type {
    BrowserActionStorageCustody,
    BrowserActionStorageRootBinding,
} from '#packages/protocol/src/runtime/browser-action-storage-custody';
import { openBrowserActionStorageCustodyWorker } from '#packages/protocol/src/runtime/browser-action-storage-custody-worker-channel';

const transactionLimits = {
    maximumActiveTransactionCount: 2,
    maximumLeaseByteLength: 64,
    maximumLeaseCountPerTransaction: 2,
    maximumStoredValueByteLength: 4_096,
    maximumTransactionByteLength: 128,
    maximumTransactionLifetimeMilliseconds: 10_000,
} as const;

const createBytes = (byteLength: number, seed: number): Uint8Array =>
    Uint8Array.from(
        { length: byteLength },
        (_, byteIndex) => (seed + byteIndex * 97) & 0xff,
    );

const binding: BrowserActionStorageRootBinding = Object.freeze({
    actionContextHash: createBytes(64, 31),
    ceremonyContextHash: createBytes(64, 19),
    participantId: createBytes(64, 43),
    suiteId: createBytes(64, 7),
});

type OpenedWorker = Readonly<{
    custody: BrowserActionStorageCustody;
    worker: Worker;
}>;

const custodies = new Set<BrowserActionStorageCustody>();
const databaseNames = new Set<string>();
const workers = new Set<Worker>();

const databaseName = (): string => {
    const random = new Uint8Array(16);
    crypto.getRandomValues(random);

    return `sealed-lattice-real-wasm-custody-${Array.from(random, (byte) =>
        byte.toString(16).padStart(2, '0'),
    ).join('')}`;
};

const openWorker = async (input: {
    binding?: BrowserActionStorageRootBinding;
    databaseName: string;
    knownStorageRootCommitment?: Uint8Array;
}): Promise<OpenedWorker> => {
    const worker = new Worker(
        new URL(
            '../support/real-wasm-action-storage-custody-browser-worker.ts',
            import.meta.url,
        ),
        { type: 'module' },
    );
    workers.add(worker);
    databaseNames.add(input.databaseName);
    const custody = await openBrowserActionStorageCustodyWorker({
        configuration: {
            binding: input.binding ?? binding,
            databaseName: input.databaseName,
            knownStorageRootCommitment: input.knownStorageRootCommitment,
            limits: transactionLimits,
            namespace: 'real-wasm-custody',
        },
        worker,
    });
    custodies.add(custody);

    return { custody, worker };
};

const crashWorker = (opened: OpenedWorker): void => {
    custodies.delete(opened.custody);
    workers.delete(opened.worker);
    opened.worker.terminate();
};

const closeWorker = async (opened: OpenedWorker): Promise<void> => {
    try {
        await opened.custody.close();
    } finally {
        custodies.delete(opened.custody);
        workers.delete(opened.worker);
        opened.worker.terminate();
    }
};

const deleteDatabase = (name: string): Promise<void> =>
    new Promise<void>((resolve, reject) => {
        const request = indexedDB.deleteDatabase(name);
        request.addEventListener('success', () => resolve(), { once: true });
        request.addEventListener(
            'error',
            () =>
                reject(
                    request.error ??
                        new Error('IndexedDB custody cleanup failed.'),
                ),
            { once: true },
        );
        request.addEventListener(
            'blocked',
            () => reject(new Error('IndexedDB custody cleanup was blocked.')),
            { once: true },
        );
    });

afterEach(async () => {
    for (const custody of custodies) {
        try {
            await custody.close();
        } catch {
            // Termination below still releases worker-owned browser resources.
        }
    }
    custodies.clear();
    for (const worker of workers) {
        worker.terminate();
    }
    workers.clear();
    for (const name of databaseNames) {
        await deleteDatabase(name);
    }
    databaseNames.clear();
});

describe('Local storage-root real-WASM browser worker', () => {
    it('completes the ordered crash, recovery, and binding-refusal lifecycle', async () => {
        {
            const primaryDatabaseName = databaseName();
            const first = await openWorker({
                databaseName: primaryDatabaseName,
            });
            const initialSnapshot = await first.custody.initialize();
            expect(initialSnapshot.storageRootCommitment).toHaveLength(64);
            crashWorker(first);

            const reopened = await openWorker({
                databaseName: primaryDatabaseName,
                knownStorageRootCommitment:
                    initialSnapshot.storageRootCommitment,
            });
            expect(await reopened.custody.currentSnapshot()).toEqual(
                initialSnapshot,
            );
            const wrongCommitment =
                initialSnapshot.storageRootCommitment.slice();
            wrongCommitment[63] ^= 1;
            await expect(
                reopened.custody.openIntoOwnedWorker({
                    expectedSnapshot: initialSnapshot,
                    externallyVerifiedCommitment: {
                        storageRootCommitment: wrongCommitment,
                    },
                }),
            ).rejects.toMatchObject({ code: 'CommitmentMismatch' });
            await reopened.custody.openIntoOwnedWorker({
                expectedSnapshot: initialSnapshot,
                externallyVerifiedCommitment: {
                    storageRootCommitment:
                        initialSnapshot.storageRootCommitment,
                },
            });
            await closeWorker(reopened);
        }

        {
            const recoveryDatabaseName = databaseName();
            const opened = await openWorker({
                databaseName: recoveryDatabaseName,
            });
            const initialSnapshot = await opened.custody.initialize();
            const externallyVerifiedCommitment = {
                storageRootCommitment: initialSnapshot.storageRootCommitment,
            };
            const challenge = await opened.custody.beginRecoveryExport({
                expectedSnapshot: initialSnapshot,
                externallyVerifiedCommitment,
            });
            const confirmation = await opened.custody.confirmRecoveryExport({
                confirmedChecksum: challenge.recoveryChecksum,
                preparationIdentifier: challenge.preparationIdentifier,
            });
            expect(confirmation.canonicalRecoveryText).toMatch(
                /^[A-Z2-7]{708}$/u,
            );

            await opened.custody.delete(confirmation.snapshot);
            expect(await opened.custody.currentSnapshot()).toBeUndefined();
            const recoveredSnapshot = await opened.custody.recover({
                caseInsensitiveRecoveryText:
                    confirmation.canonicalRecoveryText.toLowerCase(),
                externallyVerifiedCommitment,
            });
            expect(recoveredSnapshot.storageRootCommitment).toEqual(
                initialSnapshot.storageRootCommitment,
            );
            await closeWorker(opened);
        }

        {
            const sourceDatabaseName = databaseName();
            const source = await openWorker({
                databaseName: sourceDatabaseName,
            });
            const initialSnapshot = await source.custody.initialize();
            const challenge = await source.custody.beginRecoveryExport({
                expectedSnapshot: initialSnapshot,
                externallyVerifiedCommitment: {
                    storageRootCommitment:
                        initialSnapshot.storageRootCommitment,
                },
            });
            const confirmation = await source.custody.confirmRecoveryExport({
                confirmedChecksum: challenge.recoveryChecksum,
                preparationIdentifier: challenge.preparationIdentifier,
            });
            await closeWorker(source);

            const wrongBindingWorker = await openWorker({
                binding: {
                    ...binding,
                    participantId: createBytes(64, 44),
                },
                databaseName: databaseName(),
                knownStorageRootCommitment:
                    initialSnapshot.storageRootCommitment,
            });
            await expect(
                wrongBindingWorker.custody.recover({
                    caseInsensitiveRecoveryText:
                        confirmation.canonicalRecoveryText,
                    externallyVerifiedCommitment: {
                        storageRootCommitment:
                            initialSnapshot.storageRootCommitment,
                    },
                }),
            ).rejects.toMatchObject({ code: 'CommitmentMismatch' });
            await closeWorker(wrongBindingWorker);
        }
    });
});
