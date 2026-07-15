import {
    BrowserActionStorageCustodyError,
    stateCapabilityKinds,
} from '@sealed-lattice/types';
import { afterEach, describe, expect, it } from 'vitest';

import type {
    BrowserActionStorageCustody,
    BrowserActionStorageRootBinding,
} from '#packages/protocol/src/runtime/browser-action-storage-custody';
import { openBrowserActionStorageCustodyWorker } from '#packages/protocol/src/runtime/browser-action-storage-custody-worker-channel';
import {
    createWasmBrowserActionStorageWorkerKernel,
    loadFreshTranscriptCoreKernel,
} from '#packages/wasm/src/index';
import {
    createStateVerifierTestVector,
    deriveSetupActionRandomnessAuthorization,
} from '#packages/wasm/tests/state-verifier-test-vectors';

const transactionLimits = {
    maximumActiveTransactionCount: 2,
    maximumLeaseByteLength: 64,
    maximumLeaseCountPerTransaction: 2,
    maximumOwnedRecordCount: 32,
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

const expectCustodyErrorCode = async (
    operation: Promise<unknown>,
    code: BrowserActionStorageCustodyError['code'],
): Promise<void> => {
    await expect(operation).rejects.toMatchObject({
        code,
        name: 'BrowserActionStorageCustodyError',
    });
};

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
    it('retains state reservations and sealed action randomness inside the worker', async () => {
        const baseStateVector = createStateVerifierTestVector();
        const opened = await openWorker({
            binding: {
                actionContextHash: baseStateVector.actionContextHash,
                ceremonyContextHash: baseStateVector.ceremonyContextHash,
                participantId: baseStateVector.subjectParticipantIdentity,
                suiteId: baseStateVector.suiteIdentifier,
            },
            databaseName: databaseName(),
        });
        const storageSnapshot = await opened.custody.initialize();
        await opened.custody.openIntoOwnedWorker({
            expectedSnapshot: storageSnapshot,
            untrustedExpectedCommitment: {
                storageRootCommitment: storageSnapshot.storageRootCommitment,
            },
        });
        const created = await opened.custody.createAndSealActionRandomness({
            recordVersion: 0n,
        });
        const stateVector = createStateVerifierTestVector({
            setupActionRandomnessAuthorizationHash:
                deriveSetupActionRandomnessAuthorization(
                    baseStateVector,
                    created.actionRandomnessCommitment,
                ),
        });
        const stateSession =
            await opened.custody.openActionStateVerifierSession({
                canonicalRosterBytes: stateVector.canonicalRosterBytes,
            });
        if (!stateSession.isValid) {
            throw new Error('Worker state-verifier session did not open.');
        }
        const rootReservationVector = stateVector.reservationOnly.find(
            ({ capabilityKind }) =>
                capabilityKind ===
                stateCapabilityKinds.setupActionRandomnessRoot,
        );
        if (rootReservationVector === undefined) {
            throw new Error('Missing action-randomness reservation vector.');
        }
        const rootReservation =
            await opened.custody.verifyActionRandomnessReservation({
                actionRandomnessSessionIdentifier:
                    created.actionRandomnessSessionIdentifier,
                canonicalReservationIntentCarrier:
                    rootReservationVector.certifiedIntent
                        .canonicalIntentCarrier,
                canonicalStateCertificate:
                    rootReservationVector.certifiedIntent
                        .canonicalStateCertificate,
                stateVerifierSessionIdentifier: stateSession.value,
            });
        if (!rootReservation.isValid) {
            throw new Error(
                'Worker action-randomness reservation did not verify.',
            );
        }
        expect(created.actionRandomnessCommitment).toHaveLength(64);
        expect(created.canonicalEnvelope.length).toBeGreaterThan(64);
        expect(created.actionRandomnessSessionIdentifier).toMatch(
            /^[0-9a-f]{64}$/u,
        );
        await opened.custody.closeActionRandomness(
            created.actionRandomnessSessionIdentifier,
        );
        const reopened = await opened.custody.openSealedActionRandomness({
            actionRandomnessCommitment: created.actionRandomnessCommitment,
            canonicalEnvelope: created.canonicalEnvelope,
            recordVersion: 0n,
        });
        expect(reopened.actionRandomnessCommitment).toEqual(
            created.actionRandomnessCommitment,
        );
        const dealerReservationVector = stateVector.reservationOnly.find(
            ({ capabilityKind }) =>
                capabilityKind === stateCapabilityKinds.setupActionRandomnessRoot,
        );
        if (dealerReservationVector === undefined) {
            throw new Error('Missing dealer-set reservation vector.');
        }
        const dealerReservation =
            await opened.custody.verifyActionStateReservation({
                canonicalReservationIntentCarrier:
                    dealerReservationVector.certifiedIntent
                        .canonicalIntentCarrier,
                canonicalStateCertificate:
                    dealerReservationVector.certifiedIntent
                        .canonicalStateCertificate,
                capabilityKind: stateCapabilityKinds.setupActionRandomnessRoot,
                expectedAuthorizationHash: stateVector.authorizationHash,
                stateVerifierSessionIdentifier: stateSession.value,
                subjectParticipantIdentity:
                    stateVector.subjectParticipantIdentity,
            });
        const targetReservation =
            await opened.custody.verifyActionStateReservation({
                canonicalReservationIntentCarrier:
                    stateVector.reservation.canonicalIntentCarrier,
                canonicalStateCertificate:
                    stateVector.reservation.canonicalStateCertificate,
                capabilityKind: stateCapabilityKinds.targetRelease,
                expectedAuthorizationHash: stateVector.authorizationHash,
                stateVerifierSessionIdentifier: stateSession.value,
                subjectParticipantIdentity:
                    stateVector.subjectParticipantIdentity,
            });
        if (!dealerReservation.isValid || !targetReservation.isValid) {
            throw new Error(
                'Browser worker proof-attempt reservations did not verify.',
            );
        }
        const persistentAttemptInput = {
            actionRandomnessSessionIdentifier:
                reopened.actionRandomnessSessionIdentifier,
            applicationStatementHash: createBytes(64, 177),
            rosterPosition: 0,
            stateReservationIdentifier: dealerReservation.value,
            statementSchemaIdentifier: 0x1211,
        } as const;
        expect(
            await opened.custody.derivePersistentProofAttempt(
                persistentAttemptInput,
            ),
        ).toEqual(
            await opened.custody.derivePersistentProofAttempt(
                persistentAttemptInput,
            ),
        );
        const targetAttemptInput = {
            actionRandomnessSessionIdentifier:
                reopened.actionRandomnessSessionIdentifier,
            rosterPosition: 0,
            stateReservationIdentifier: targetReservation.value,
        } as const;
        expect(
            await opened.custody.deriveTargetReleaseAttempt(targetAttemptInput),
        ).toEqual(
            await opened.custody.deriveTargetReleaseAttempt(targetAttemptInput),
        );
        await expectCustodyErrorCode(
            opened.custody.deriveTargetReleaseAttempt({
                ...targetAttemptInput,
                stateReservationIdentifier: rootReservation.value,
            }),
            'InvalidState',
        );
        await opened.custody.closeActionRandomness(
            reopened.actionRandomnessSessionIdentifier,
        );
        await opened.custody.closeActionStateVerifierSession(
            stateSession.value,
        );
        await closeWorker(opened);
    });

    it('authenticates local-record envelopes in the browser WASM runtime', async () => {
        const workerKernel = createWasmBrowserActionStorageWorkerKernel({
            kernel: loadFreshTranscriptCoreKernel(),
        });
        await workerKernel.createAndStageDeviceWrappingState({ binding });
        await workerKernel.commitStagedActionStorageRoot();

        const expectedContext = {
            actionRandomnessCommitment: createBytes(64, 127),
            identifierInput: {
                recordType: 'subjectState',
                stateKey: createBytes(64, 131),
            },
            recordVersion: 0n,
        } as const;
        const plaintext = createBytes(8_193, 137);
        const envelope = await workerKernel.sealActiveLocalRecord({
            ...expectedContext,
            plaintext,
        });
        expect(
            await workerKernel.openActiveLocalRecord({
                ...expectedContext,
                envelope,
            }),
        ).toEqual(plaintext);
        expect(
            await workerKernel.hashActiveLocalRecordEnvelope(envelope),
        ).toHaveLength(64);

        const tamperedEnvelope = envelope.slice();
        tamperedEnvelope[tamperedEnvelope.length - 17] ^= 1;
        await expectCustodyErrorCode(
            workerKernel.openActiveLocalRecord({
                ...expectedContext,
                envelope: tamperedEnvelope,
            }),
            'RecordAuthenticationFailed',
        );
        await workerKernel.destroyActiveActionStorageRoot();
    });

    it('reopens local state after a crash and refuses a wrong commitment', async () => {
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
                    untrustedExpectedCommitment: {
                        storageRootCommitment: wrongCommitment,
                    },
                }),
            ).rejects.toMatchObject({ code: 'CommitmentMismatch' });
            await reopened.custody.openIntoOwnedWorker({
                expectedSnapshot: initialSnapshot,
                untrustedExpectedCommitment: {
                    storageRootCommitment:
                        initialSnapshot.storageRootCommitment,
                },
            });
            await closeWorker(reopened);
        }

    });
});
