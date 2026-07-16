import { afterEach, describe, expect, it } from 'vitest';

import type {
    BrowserActionStorageCustody,
    BrowserActionStorageRootBinding,
    BrowserFoundationCheckpointHandle,
    BrowserFoundationStorageAuthority,
    UntrustedExpectedStorageRootCommitment,
} from '#packages/protocol/src/runtime/browser-action-storage-custody';
import {
    openBrowserActionStorageCustodyWorker,
    openBrowserFoundationOperationOwnerWorker,
} from '#packages/protocol/src/runtime/browser-action-storage-custody-worker-channel';
import type {
    BrowserFoundationInitializationInput,
    BrowserFoundationOperationOwner,
} from '#packages/protocol/src/runtime/browser-foundation-operation-owner';
import { deriveWebLockStorageNamespaceName } from '#packages/protocol/src/runtime/web-lock-owned-untrusted-storage-transaction-store';
import { createTestBytes } from '#packages/protocol/tests/support/action-storage-custody-test-support';
import {
    asciiItem,
    canonicalItem,
    canonicalTuple,
    concatenateBytes,
    foundationHash512,
    hashItem,
    unsigned16LittleEndian,
    unsigned32LittleEndian,
    unsigned64Item,
    variableBytesItem,
} from '#packages/wasm/tests/canonical-tuple-test-helpers';

const transactionLimits = {
    maximumActiveTransactionCount: 2,
    maximumLeaseByteLength: 65_536,
    maximumLeaseCountPerTransaction: 32,
    maximumOwnedRecordCount: 256,
    maximumStoredValueByteLength: 4_194_304,
    maximumTransactionByteLength: 1_048_576,
    maximumTransactionLifetimeMilliseconds: 10_000,
} as const;
const testBinding: BrowserActionStorageRootBinding = Object.freeze({
    actionContextHash: createTestBytes(64, 41),
    ceremonyContextHash: createTestBytes(64, 23),
    participantId: createTestBytes(64, 59),
    suiteId: createTestBytes(64, 7),
});
const runtimeBuildManifestHash = createTestBytes(64, 83);
const checkpointStateStreamDomain =
    'sealed-lattice/test/browser-checkpoint-state/v1';

const checkpointStateDescriptor = (stateBytes: Uint8Array): Uint8Array => {
    const chunkDigest = foundationHash512(
        'sealed-lattice/transport/chunk/v1',
        asciiItem(checkpointStateStreamDomain),
        canonicalItem(0x04, unsigned32LittleEndian(0)),
        canonicalItem(0x04, unsigned32LittleEndian(stateBytes.byteLength)),
        variableBytesItem(stateBytes),
    );
    const fullObjectDigest = foundationHash512(
        'sealed-lattice/transport/full-object/v1',
        asciiItem(checkpointStateStreamDomain),
        unsigned64Item(BigInt(stateBytes.byteLength)),
        variableBytesItem(stateBytes),
    );
    return canonicalTuple(
        0x1800,
        unsigned64Item(BigInt(stateBytes.byteLength)),
        canonicalItem(
            0x0e,
            concatenateBytes(
                unsigned16LittleEndian(0x06),
                unsigned32LittleEndian(1),
                chunkDigest,
            ),
        ),
        hashItem(fullObjectDigest),
    );
};

const untrustedExpectedCommitment = (
    storageRootCommitment: Uint8Array,
): UntrustedExpectedStorageRootCommitment =>
    Object.freeze({ storageRootCommitment: storageRootCommitment.slice() });

type OpeningWorker = Readonly<{
    opening: Promise<BrowserFoundationStorageAuthority>;
    worker: Worker;
}>;

const openedCustodies = new Set<BrowserActionStorageCustody>();
const openedOperationOwners = new Set<BrowserFoundationOperationOwner>();
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
            runtimeBuildManifestHash,
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
}): Promise<BrowserFoundationStorageAuthority> =>
    await startOpeningWorker(input).opening;

const runFoundationWitnessStorageBoundaryWorker = (
    databaseName: string,
): Promise<void> => {
    const worker = new Worker(
        new URL(
            '../support/foundation-witness-storage-boundary-browser-worker.ts',
            import.meta.url,
        ),
        { type: 'module' },
    );
    openedWorkers.add(worker);
    databaseNames.add(databaseName);
    return new Promise<void>((resolve, reject) => {
        worker.addEventListener(
            'error',
            (event) => {
                reject(
                    event.error instanceof Error
                        ? event.error
                        : new Error(
                              event.message ||
                                  'The foundation witness boundary worker failed.',
                          ),
                );
            },
            { once: true },
        );
        worker.addEventListener(
            'message',
            (event: MessageEvent<unknown>) => {
                const result = event.data as {
                    error?: unknown;
                    success?: unknown;
                };
                if (result.success === true) {
                    resolve();
                    return;
                }
                reject(
                    new Error(
                        typeof result.error === 'string'
                            ? result.error
                            : 'The foundation witness boundary worker returned a malformed failure.',
                    ),
                );
            },
            { once: true },
        );
        worker.postMessage({ databaseName });
    });
};

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
        throw new Error('The custody Web Lock availability probe did not run.');
    }
    return lockWasAvailable;
};

const waitForExclusiveLockRelease = (lockName: string): Promise<void> =>
    navigator.locks.request(lockName, { mode: 'exclusive' }, () => undefined);

afterEach(async () => {
    for (const operationOwner of [...openedOperationOwners]) {
        try {
            await operationOwner.close();
        } catch {
            // The worker is terminated below even if orderly close failed.
        }
    }
    openedOperationOwners.clear();
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
    it('enforces the root-backed witness payload budget and retries after a sealed record is abandoned', async () => {
        await expect(
            runFoundationWitnessStorageBoundaryWorker(createDatabaseName()),
        ).resolves.toBeUndefined();
    }, 30_000);

    it('opens the composed operation owner from fresh and exact recovered storage after interruption', async () => {
        const databaseName = createDatabaseName();
        databaseNames.add(databaseName);
        const orderedWitnessBindings = Array.from(
            { length: 9 },
            (_unused, witnessIndex) => ({
                subjectParticipantIdentity: createTestBytes(
                    64,
                    101 + witnessIndex,
                ),
                witnessParticipantIdentity: testBinding.participantId.slice(),
            }),
        );
        const initializationInput: BrowserFoundationInitializationInput =
            Object.freeze({
                actionRandomnessRecordContext: { recordVersion: 0n },
                canonicalRosterBytes: createTestBytes(640, 11),
                orderedWitnessBindings,
                runtimeBuildManifestHash,
            });
        const freshWorker = new Worker(
            new URL(
                '../support/action-storage-custody-browser-worker.ts',
                import.meta.url,
            ),
            { type: 'module' },
        );
        openedWorkers.add(freshWorker);
        const freshOpening = await openBrowserFoundationOperationOwnerWorker({
            configuration: {
                acquisitionDeadlineEpochMilliseconds: undefined,
                binding: testBinding,
                databaseName,
                limits: transactionLimits,
                namespace: 'browser-custody',
                runtimeBuildManifestHash,
            },
            rootOpening: { mode: 'fresh' },
            worker: freshWorker,
        });
        openedOperationOwners.add(freshOpening.operationOwner);
        const committed =
            await freshOpening.operationOwner.commitFreshFoundationInitialization(
                initializationInput,
            );
        const freshActivated =
            await freshOpening.operationOwner.activateFreshFoundationInitialization(
                committed.committedBatch,
            );
        expect(freshActivated.orderedWitnessRoleHandles).toHaveLength(9);
        const firstFreshRole = freshActivated.orderedWitnessRoleHandles[0];
        if (firstFreshRole === undefined) {
            throw new Error('The fresh operation owner returned no role.');
        }
        await expect(
            freshOpening.operationOwner.copyWitnessSubjectParticipantIdentity(
                firstFreshRole,
            ),
        ).resolves.toEqual(
            orderedWitnessBindings[0]?.subjectParticipantIdentity,
        );
        openedOperationOwners.delete(freshOpening.operationOwner);
        openedWorkers.delete(freshWorker);
        freshWorker.terminate();
        await waitForExclusiveLockRelease(
            deriveWebLockStorageNamespaceName({
                databaseName,
                namespace: 'browser-custody',
            }),
        );

        const recoveredWorker = new Worker(
            new URL(
                '../support/action-storage-custody-browser-worker.ts',
                import.meta.url,
            ),
            { type: 'module' },
        );
        openedWorkers.add(recoveredWorker);
        const recoveredOpening =
            await openBrowserFoundationOperationOwnerWorker({
                configuration: {
                    acquisitionDeadlineEpochMilliseconds: undefined,
                    binding: testBinding,
                    databaseName,
                    knownStorageRootCommitment:
                        freshOpening.deviceWrappingSnapshot
                            .storageRootCommitment,
                    limits: transactionLimits,
                    namespace: 'browser-custody',
                    runtimeBuildManifestHash,
                },
                rootOpening: {
                    expectedSnapshot: freshOpening.deviceWrappingSnapshot,
                    mode: 'recovered',
                    untrustedExpectedCommitment: untrustedExpectedCommitment(
                        freshOpening.deviceWrappingSnapshot
                            .storageRootCommitment,
                    ),
                },
                worker: recoveredWorker,
            });
        openedOperationOwners.add(recoveredOpening.operationOwner);
        const recovered =
            await recoveredOpening.operationOwner.openRecoveredFoundationInitialization(
                initializationInput,
            );
        const recoveredActivated =
            await recoveredOpening.operationOwner.activateRecoveredFoundationInitialization(
                recovered.recoveredBatch,
            );
        await expect(
            Promise.all(
                recoveredActivated.orderedWitnessRoleHandles.map((role) =>
                    recoveredOpening.operationOwner.copyWitnessSubjectParticipantIdentity(
                        role,
                    ),
                ),
            ),
        ).resolves.toEqual(
            orderedWitnessBindings.map(
                (binding) => binding.subjectParticipantIdentity,
            ),
        );
        await recoveredOpening.operationOwner.closeFoundationActionRandomness(
            recoveredActivated.actionRandomnessHandle,
        );
        await recoveredOpening.operationOwner.close();
        openedOperationOwners.delete(recoveredOpening.operationOwner);
    }, 30_000);

    it('persists, reopens, and deletes custody state', async () => {
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
        await secondCustody.delete(initialSnapshot);
        expect(await secondCustody.currentSnapshot()).toBeUndefined();
        await expect(secondCustody.initialize()).rejects.toMatchObject({
            code: 'CommitmentRequired',
        });
        await expect(
            secondCustody.openIntoOwnedWorker({
                expectedSnapshot: initialSnapshot,
                untrustedExpectedCommitment: commitment,
            }),
        ).rejects.toMatchObject({ code: 'Unavailable' });
    });

    it('persists retirement without retaining wrapping material and refuses every reopening mode', async () => {
        const databaseName = createDatabaseName();
        const firstCustody = await openWorker({ databaseName });
        const snapshot = await firstCustody.initialize();
        const commitment = untrustedExpectedCommitment(
            snapshot.storageRootCommitment,
        );
        await firstCustody.openIntoOwnedWorker({
            expectedSnapshot: snapshot,
            untrustedExpectedCommitment: commitment,
        });

        await firstCustody.retire();
        await expect(firstCustody.currentSnapshot()).rejects.toMatchObject({
            code: 'Unavailable',
        });
        await closeCustody(firstCustody);

        const freshCustody = await openWorker({ databaseName });
        await expect(freshCustody.initialize()).rejects.toMatchObject({
            code: 'Unavailable',
        });
        await closeCustody(freshCustody);

        const recoveredCustody = await openWorker({
            databaseName,
            knownStorageRootCommitment: snapshot.storageRootCommitment,
        });
        await expect(
            recoveredCustody.openIntoOwnedWorker({
                expectedSnapshot: snapshot,
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
                envelope,
            }),
        ).resolves.toEqual(plaintext);
        await expect(
            custody.sealLocalRecord({
                ...expectedContext,
                predecessorRecordHash: createTestBytes(64, 149),
                plaintext,
            }),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
    });

    it('keeps bounded checkpoint writes on a distinct authenticated worker-owned head', async () => {
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
        const committed = await custody.commitFreshFoundationInitialization({
            actionRandomnessRecordContext: { recordVersion: 0n },
            orderedWitnessBindings: Array.from(
                { length: 9 },
                (_unused, witnessIndex) => ({
                    subjectParticipantIdentity: createTestBytes(
                        64,
                        101 + witnessIndex,
                    ),
                    witnessParticipantIdentity:
                        testBinding.participantId.slice(),
                }),
            ),
            runtimeBuildManifestHash,
        });
        const foundationHeadBeforeCheckpoint =
            await custody.authenticateFoundationHead();
        expect(committed.freshnessCoordinate).toEqual(
            foundationHeadBeforeCheckpoint,
        );

        const checkpoint = await custody.beginCheckpoint([]);
        await expect(
            custody.copyCheckpointDescription(
                Object.freeze({}) as BrowserFoundationCheckpointHandle,
            ),
        ).rejects.toMatchObject({ code: 'InvalidInput' });
        const boundary = {
            operationKind: 1,
            orderedRandomCursors: [],
            orderedSourceDigests: [],
            safeBoundaryOrdinal: 0,
            stateStreamDescriptorBytes: checkpointStateDescriptor(
                Uint8Array.of(0x5a),
            ),
            stateStreamDomain: checkpointStateStreamDomain,
        } as const;
        const canonicalManifestBytes = await custody.publishCheckpoint(
            checkpoint,
            { boundary, stateChunks: [Uint8Array.of(0x5a)] },
        );
        expect(canonicalManifestBytes.byteLength).toBeGreaterThan(0);
        expect(await custody.authenticateFoundationHead()).toEqual(
            foundationHeadBeforeCheckpoint,
        );

        const description = await custody.copyCheckpointDescription(checkpoint);
        const resumed = await custody.resumeCheckpoint({
            checkpointLineageIdentifier:
                description.checkpointLineageIdentifier,
            expectedBoundary: {
                operationKind: boundary.operationKind,
                orderedRandomCursors: boundary.orderedRandomCursors,
                orderedSourceDigests: boundary.orderedSourceDigests,
                safeBoundaryOrdinal: boundary.safeBoundaryOrdinal,
                stateStreamDomain: boundary.stateStreamDomain,
            },
        });
        const consumerFailure = new Error(
            'The checkpoint consumer rejected restored state.',
        );
        await expect(
            custody.restoreCheckpointState(resumed, () => {
                throw consumerFailure;
            }),
        ).rejects.toBe(consumerFailure);

        const restoredChunks: Uint8Array[] = [];
        await custody.restoreCheckpointState(
            resumed,
            (_chunkIndex, chunkBytes) => {
                restoredChunks.push(chunkBytes);
            },
        );
        expect(restoredChunks).toEqual([Uint8Array.of(0x5a)]);
        expect(await custody.authenticateFoundationHead()).toEqual(
            foundationHeadBeforeCheckpoint,
        );
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

        expect(await exclusiveLockIsAvailable(lockName)).toBe(false);
        await closeCustody(firstCustody);
        const secondCustody = await secondOpening.opening;
        expect(await exclusiveLockIsAvailable(lockName)).toBe(false);
        expect(await secondCustody.currentSnapshot()).toEqual(snapshot);
        await secondCustody.openIntoOwnedWorker({
            expectedSnapshot: snapshot,
            untrustedExpectedCommitment: commitment,
        });
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
        await waitForExclusiveLockRelease(lockName);
    }, 15_000);
});
