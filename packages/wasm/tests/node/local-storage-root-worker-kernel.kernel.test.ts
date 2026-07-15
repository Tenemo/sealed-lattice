import {
    BrowserActionStorageCustodyError,
    stateCapabilityKinds,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    createWasmBrowserActionStorageWorkerKernel,
    loadFreshTranscriptCoreKernel,
} from '#packages/wasm/src/index';
import {
    closeWorkerActionRandomness,
    createAndSealWorkerActionRandomness,
    openSealedWorkerActionRandomness,
} from '#packages/wasm/src/local-storage-root-worker-kernel';
import {
    createStateVerifierTestVector,
    deriveSetupActionRandomnessAuthorization,
} from '#packages/wasm/tests/state-verifier-test-vectors';

const createBytes = (byteLength: number, seed: number): Uint8Array =>
    Uint8Array.from(
        { length: byteLength },
        (_, byteIndex) => (seed + byteIndex * 97) & 0xff,
    );

const binding = Object.freeze({
    actionContextHash: createBytes(64, 31),
    ceremonyContextHash: createBytes(64, 19),
    participantId: createBytes(64, 43),
    suiteId: createBytes(64, 7),
});

const mutationIdentifier = createBytes(32, 113);

const expectCustodyErrorCode = async (
    operation: Promise<unknown>,
    code: BrowserActionStorageCustodyError['code'],
): Promise<void> => {
    await expect(operation).rejects.toMatchObject({
        code,
        name: 'BrowserActionStorageCustodyError',
    });
};

describe('Local storage-root real-WASM worker kernel', () => {
    it('seals and reopens action randomness without exposing its root plaintext', async () => {
        const baseStateVector = createStateVerifierTestVector();
        const actionBinding = Object.freeze({
            actionContextHash: baseStateVector.actionContextHash,
            ceremonyContextHash: baseStateVector.ceremonyContextHash,
            participantId: baseStateVector.subjectParticipantIdentity,
            suiteId: baseStateVector.suiteIdentifier,
        });
        const workerKernel = createWasmBrowserActionStorageWorkerKernel({
            kernel: loadFreshTranscriptCoreKernel(),
        });
        await workerKernel.createAndStageDeviceWrappingState({
            binding: actionBinding,
        });
        await workerKernel.commitStagedActionStorageRoot({
            mutationIdentifier,
        });
        const recordContext = {
            creationRecoveryEpoch: 0n,
            recordVersion: 0n,
        } as const;
        const created = await createAndSealWorkerActionRandomness(
            workerKernel,
            recordContext,
        );
        const stateVector = createStateVerifierTestVector({
            setupActionRandomnessAuthorizationHash:
                deriveSetupActionRandomnessAuthorization(
                    baseStateVector,
                    created.actionRandomnessCommitment,
                ),
        });
        const openedStateSession =
            await workerKernel.openActionStateVerifierSession({
                canonicalRosterBytes: stateVector.canonicalRosterBytes,
                maximumRecoveryTransitionsPerStateKey: 4,
            });
        expect(openedStateSession.isValid).toBe(true);
        if (!openedStateSession.isValid) {
            throw new Error('State-verifier session did not open.');
        }
        const mismatchedRootReservationVector =
            baseStateVector.reservationOnly.find(
                ({ capabilityKind }) =>
                    capabilityKind ===
                    stateCapabilityKinds.setupActionRandomnessRoot,
            );
        if (mismatchedRootReservationVector === undefined) {
            throw new Error('Missing mismatched action-randomness vector.');
        }
        expect(
            await workerKernel.verifyActionRandomnessReservation({
                actionRandomnessSessionIdentifier:
                    created.actionRandomnessSessionIdentifier,
                canonicalReservationIntentCarrier:
                    mismatchedRootReservationVector.certifiedIntent
                        .canonicalIntentCarrier,
                canonicalStateCertificate:
                    mismatchedRootReservationVector.certifiedIntent
                        .canonicalStateCertificate,
                stateVerifierSessionIdentifier: openedStateSession.value,
            }),
        ).toEqual({ isValid: false, refusalReason: 'wrongHashOrRoot' });
        const rootReservationVector = stateVector.reservationOnly.find(
            ({ capabilityKind }) =>
                capabilityKind ===
                stateCapabilityKinds.setupActionRandomnessRoot,
        );
        if (rootReservationVector === undefined) {
            throw new Error('Missing action-randomness reservation vector.');
        }
        const rootReservation =
            await workerKernel.verifyActionRandomnessReservation({
                actionRandomnessSessionIdentifier:
                    created.actionRandomnessSessionIdentifier,
                canonicalReservationIntentCarrier:
                    rootReservationVector.certifiedIntent
                        .canonicalIntentCarrier,
                canonicalStateCertificate:
                    rootReservationVector.certifiedIntent
                        .canonicalStateCertificate,
                stateVerifierSessionIdentifier: openedStateSession.value,
            });
        expect(rootReservation.isValid).toBe(true);
        if (!rootReservation.isValid) {
            throw new Error('Action-randomness reservation did not verify.');
        }
        expect(created.actionRandomnessCommitment).toHaveLength(64);
        expect(created.canonicalEnvelope.length).toBeGreaterThan(64);
        await closeWorkerActionRandomness(
            workerKernel,
            created.actionRandomnessSessionIdentifier,
        );
        const reopened = await openSealedWorkerActionRandomness(workerKernel, {
            ...recordContext,
            actionRandomnessCommitment: created.actionRandomnessCommitment,
            canonicalEnvelope: created.canonicalEnvelope,
        });
        expect(reopened.actionRandomnessCommitment).toEqual(
            created.actionRandomnessCommitment,
        );
        const dealerReservationVector = stateVector.reservationOnly.find(
            ({ capabilityKind }) =>
                capabilityKind === stateCapabilityKinds.setupDealerSetBranch,
        );
        if (dealerReservationVector === undefined) {
            throw new Error('Missing dealer-set reservation vector.');
        }
        const dealerReservation =
            await workerKernel.verifyActionStateReservation({
                canonicalReservationIntentCarrier:
                    dealerReservationVector.certifiedIntent
                        .canonicalIntentCarrier,
                canonicalStateCertificate:
                    dealerReservationVector.certifiedIntent
                        .canonicalStateCertificate,
                capabilityKind: stateCapabilityKinds.setupDealerSetBranch,
                expectedAuthorizationHash: stateVector.authorizationHash,
                stateVerifierSessionIdentifier: openedStateSession.value,
                subjectParticipantIdentity:
                    stateVector.subjectParticipantIdentity,
            });
        const targetReservation =
            await workerKernel.verifyActionStateReservation({
                canonicalReservationIntentCarrier:
                    stateVector.reservation.canonicalIntentCarrier,
                canonicalStateCertificate:
                    stateVector.reservation.canonicalStateCertificate,
                capabilityKind: stateCapabilityKinds.targetRelease,
                expectedAuthorizationHash: stateVector.authorizationHash,
                stateVerifierSessionIdentifier: openedStateSession.value,
                subjectParticipantIdentity:
                    stateVector.subjectParticipantIdentity,
            });
        if (!dealerReservation.isValid || !targetReservation.isValid) {
            throw new Error('Proof-attempt reservations did not verify.');
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
            await workerKernel.derivePersistentProofAttempt(
                persistentAttemptInput,
            ),
        ).toEqual(
            await workerKernel.derivePersistentProofAttempt(
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
            await workerKernel.deriveTargetReleaseAttempt(targetAttemptInput),
        ).toEqual(
            await workerKernel.deriveTargetReleaseAttempt(targetAttemptInput),
        );
        await expectCustodyErrorCode(
            workerKernel.deriveTargetReleaseAttempt({
                ...targetAttemptInput,
                stateReservationIdentifier: rootReservation.value,
            }),
            'InvalidState',
        );
        await closeWorkerActionRandomness(
            workerKernel,
            reopened.actionRandomnessSessionIdentifier,
        );

        const tamperedEnvelope = created.canonicalEnvelope.slice();
        tamperedEnvelope[tamperedEnvelope.byteLength - 1] ^= 1;
        await expectCustodyErrorCode(
            openSealedWorkerActionRandomness(workerKernel, {
                ...recordContext,
                actionRandomnessCommitment: created.actionRandomnessCommitment,
                canonicalEnvelope: tamperedEnvelope,
            }),
            'RecordAuthenticationFailed',
        );
        await expectCustodyErrorCode(
            createAndSealWorkerActionRandomness(workerKernel, {
                ...recordContext,
            }),
            'InvalidState',
        );
        await workerKernel.closeActionStateVerifierSession(
            openedStateSession.value,
        );
        await workerKernel.destroyActiveActionStorageRoot();
    });

    it('derives, seals, authenticates, versions, and hashes local records inside the owned kernel', async () => {
        const workerKernel = createWasmBrowserActionStorageWorkerKernel({
            kernel: loadFreshTranscriptCoreKernel(),
        });
        await workerKernel.createAndStageDeviceWrappingState({ binding });
        await workerKernel.commitStagedActionStorageRoot({
            mutationIdentifier,
        });

        const identifierInput = {
            applicationSlotHash: createBytes(64, 151),
            recordType: 'proofAttempt',
        } as const;
        const recordIdentifier =
            await workerKernel.deriveActiveLocalRecordIdentifier(
                identifierInput,
            );
        expect(recordIdentifier).toHaveLength(64);
        const changedRecordIdentifier =
            await workerKernel.deriveActiveLocalRecordIdentifier({
                ...identifierInput,
                applicationSlotHash: createBytes(64, 152),
            });
        expect(changedRecordIdentifier).not.toEqual(recordIdentifier);

        const versionZeroContext = {
            actionRandomnessCommitment: createBytes(64, 167),
            creationRecoveryEpoch: 7n,
            identifierInput,
            recordVersion: 0n,
        } as const;
        const plaintext = createBytes(1_013, 181);
        const envelope = await workerKernel.sealActiveLocalRecord({
            ...versionZeroContext,
            plaintext,
        });
        expect(envelope.length).toBeGreaterThan(plaintext.length);
        expect(
            await workerKernel.openActiveLocalRecord({
                ...versionZeroContext,
                envelope,
            }),
        ).toEqual(plaintext);
        const envelopeHash =
            await workerKernel.hashActiveLocalRecordEnvelope(envelope);
        expect(envelopeHash).toHaveLength(64);

        await expectCustodyErrorCode(
            workerKernel.sealActiveLocalRecord({
                ...versionZeroContext,
                plaintext: createBytes(3, 193),
            }),
            'InvalidState',
        );
        const tamperedEnvelope = envelope.slice();
        tamperedEnvelope[tamperedEnvelope.length - 1] ^= 1;
        await expectCustodyErrorCode(
            workerKernel.openActiveLocalRecord({
                ...versionZeroContext,
                envelope: tamperedEnvelope,
            }),
            'RecordAuthenticationFailed',
        );
        await expectCustodyErrorCode(
            workerKernel.openActiveLocalRecord({
                ...versionZeroContext,
                actionRandomnessCommitment: createBytes(64, 168),
                envelope,
            }),
            'RecordAuthenticationFailed',
        );

        const versionOneContext = {
            ...versionZeroContext,
            predecessorRecordHash: envelopeHash,
            recordVersion: 1n,
        } as const;
        const successorPlaintext = createBytes(257, 211);
        const successorEnvelope = await workerKernel.sealActiveLocalRecord({
            ...versionOneContext,
            plaintext: successorPlaintext,
        });
        expect(
            await workerKernel.openActiveLocalRecord({
                ...versionOneContext,
                envelope: successorEnvelope,
            }),
        ).toEqual(successorPlaintext);
        await expectCustodyErrorCode(
            workerKernel.openActiveLocalRecord({
                ...versionOneContext,
                predecessorRecordHash: createBytes(64, 212),
                envelope: successorEnvelope,
            }),
            'RecordAuthenticationFailed',
        );
        await expectCustodyErrorCode(
            workerKernel.sealActiveLocalRecord({
                ...versionZeroContext,
                plaintext: new Uint8Array(1_048_577),
            }),
            'InvalidInput',
        );
        await workerKernel.destroyActiveActionStorageRoot();
    });

    it('wraps, activates, exports, confirms, destroys, and reopens after a worker crash', async () => {
        const initialWorkerKernel = createWasmBrowserActionStorageWorkerKernel({
            kernel: loadFreshTranscriptCoreKernel(),
        });
        const prepared =
            await initialWorkerKernel.createAndStageDeviceWrappingState({
                binding,
            });

        expect(prepared.storageRootCommitment).toHaveLength(64);
        expect(prepared.wrappedStorageRoot.length).toBeGreaterThan(0);
        expect(prepared.wrappedStorageRoot.length).toBeLessThanOrEqual(492);
        expect(prepared.deviceKey.extractable).toBe(false);
        await expect(
            crypto.subtle.exportKey('raw', prepared.deviceKey),
        ).rejects.toBeDefined();

        await expectCustodyErrorCode(
            initialWorkerKernel.createAndStageDeviceWrappingState({ binding }),
            'InvalidState',
        );
        const conflictingCommitment = prepared.storageRootCommitment.slice();
        conflictingCommitment[0] ^= 1;
        await expectCustodyErrorCode(
            initialWorkerKernel.stageDeviceWrappingStateOpen({
                binding,
                untrustedExpectedCommitment: {
                    storageRootCommitment: conflictingCommitment,
                },
                state: {
                    ...prepared,
                    storageRootCommitment: conflictingCommitment,
                },
            }),
            'InvalidState',
        );
        await initialWorkerKernel.stageDeviceWrappingStateOpen({
            binding,
            untrustedExpectedCommitment: {
                storageRootCommitment: prepared.storageRootCommitment,
            },
            state: prepared,
        });
        await initialWorkerKernel.commitStagedActionStorageRoot({
            mutationIdentifier,
        });
        const recovery = await initialWorkerKernel.prepareRecoveryExport({
            activeMutationIdentifier: mutationIdentifier,
        });
        expect(recovery.canonicalRecoveryText).toMatch(/^[A-Z2-7]{708}$/u);
        expect(recovery.recoveryChecksum).toHaveLength(16);
        await expectCustodyErrorCode(
            initialWorkerKernel.prepareRecoveryExport({
                activeMutationIdentifier: createBytes(32, 114),
            }),
            'InvalidState',
        );
        const wrongChecksum = recovery.recoveryChecksum.slice();
        wrongChecksum[0] ^= 1;
        await expectCustodyErrorCode(
            initialWorkerKernel.confirmRecoveryChecksum({
                canonicalRecoveryText: recovery.canonicalRecoveryText,
                confirmedChecksum: wrongChecksum,
            }),
            'RecoveryConfirmationFailed',
        );
        await initialWorkerKernel.confirmRecoveryChecksum({
            canonicalRecoveryText: recovery.canonicalRecoveryText,
            confirmedChecksum: recovery.recoveryChecksum,
        });
        await initialWorkerKernel.destroyActiveActionStorageRoot();
        await initialWorkerKernel.destroyActiveActionStorageRoot();
        await expectCustodyErrorCode(
            initialWorkerKernel.prepareRecoveryExport({
                activeMutationIdentifier: mutationIdentifier,
            }),
            'InvalidState',
        );

        const replacementKernel = await loadFreshTranscriptCoreKernel();
        const replacementWorkerKernel =
            createWasmBrowserActionStorageWorkerKernel({
                kernel: replacementKernel,
            });
        await replacementWorkerKernel.stageDeviceWrappingStateOpen({
            binding,
            untrustedExpectedCommitment: {
                storageRootCommitment: prepared.storageRootCommitment,
            },
            state: prepared,
        });
        await replacementWorkerKernel.commitStagedActionStorageRoot({
            mutationIdentifier,
        });
        const reopenedRecovery =
            await replacementWorkerKernel.prepareRecoveryExport({
                activeMutationIdentifier: mutationIdentifier,
            });
        expect(reopenedRecovery.canonicalRecoveryText).toBe(
            recovery.canonicalRecoveryText,
        );
        expect(reopenedRecovery.recoveryChecksum).toEqual(
            recovery.recoveryChecksum,
        );
        await replacementWorkerKernel.destroyActiveActionStorageRoot();
    });

    it('refuses wrong bindings, commitments, envelopes, and stale staged state', async () => {
        const sourceKernel = await loadFreshTranscriptCoreKernel();
        const sourceWorkerKernel = createWasmBrowserActionStorageWorkerKernel({
            kernel: sourceKernel,
        });
        const prepared =
            await sourceWorkerKernel.createAndStageDeviceWrappingState({
                binding,
            });
        await sourceWorkerKernel.discardStagedActionStorageRoot();
        await sourceWorkerKernel.discardStagedActionStorageRoot();

        const openingKernel = await loadFreshTranscriptCoreKernel();
        const openingWorkerKernel = createWasmBrowserActionStorageWorkerKernel({
            kernel: openingKernel,
        });
        const wrongBinding = {
            ...binding,
            actionContextHash: createBytes(64, 32),
        };
        await expectCustodyErrorCode(
            openingWorkerKernel.stageDeviceWrappingStateOpen({
                binding: wrongBinding,
                untrustedExpectedCommitment: {
                    storageRootCommitment: prepared.storageRootCommitment,
                },
                state: prepared,
            }),
            'CommitmentMismatch',
        );

        const wrongCommitment = prepared.storageRootCommitment.slice();
        wrongCommitment[17] ^= 1;
        await expectCustodyErrorCode(
            openingWorkerKernel.stageDeviceWrappingStateOpen({
                binding,
                untrustedExpectedCommitment: {
                    storageRootCommitment: wrongCommitment,
                },
                state: prepared,
            }),
            'CommitmentMismatch',
        );

        const tamperedState = {
            ...prepared,
            wrappedStorageRoot: prepared.wrappedStorageRoot.slice(),
        };
        tamperedState.wrappedStorageRoot[
            tamperedState.wrappedStorageRoot.length - 1
        ] ^= 1;
        await expectCustodyErrorCode(
            openingWorkerKernel.stageDeviceWrappingStateOpen({
                binding,
                untrustedExpectedCommitment: {
                    storageRootCommitment: prepared.storageRootCommitment,
                },
                state: tamperedState,
            }),
            'InvalidCanonicalMaterial',
        );

        await openingWorkerKernel.stageDeviceWrappingStateOpen({
            binding,
            untrustedExpectedCommitment: {
                storageRootCommitment: prepared.storageRootCommitment,
            },
            state: prepared,
        });
        await openingWorkerKernel.discardStagedActionStorageRoot();
        await expectCustodyErrorCode(
            openingWorkerKernel.commitStagedActionStorageRoot({
                mutationIdentifier,
            }),
            'InvalidState',
        );
    });

    it('imports recovery material under the exact binding and reclaims repeated staged roots', async () => {
        const sourceKernel = await loadFreshTranscriptCoreKernel();
        const sourceWorkerKernel = createWasmBrowserActionStorageWorkerKernel({
            kernel: sourceKernel,
        });
        const prepared =
            await sourceWorkerKernel.createAndStageDeviceWrappingState({
                binding,
            });
        await sourceWorkerKernel.commitStagedActionStorageRoot({
            mutationIdentifier,
        });
        const recovery = await sourceWorkerKernel.prepareRecoveryExport({
            activeMutationIdentifier: mutationIdentifier,
        });

        const recoveryKernel = await loadFreshTranscriptCoreKernel();
        const recoveryWorkerKernel = createWasmBrowserActionStorageWorkerKernel(
            { kernel: recoveryKernel },
        );
        const wrongBinding = {
            ...binding,
            participantId: createBytes(64, 44),
        };
        await expectCustodyErrorCode(
            recoveryWorkerKernel.stageRecoveryValueImportAndDeviceWrapping({
                binding: wrongBinding,
                caseInsensitiveRecoveryText:
                    recovery.canonicalRecoveryText.toLowerCase(),
                untrustedExpectedCommitment: {
                    storageRootCommitment: prepared.storageRootCommitment,
                },
            }),
            'CommitmentMismatch',
        );
        const wrongCommitment = prepared.storageRootCommitment.slice();
        wrongCommitment[63] ^= 1;
        await expectCustodyErrorCode(
            recoveryWorkerKernel.stageRecoveryValueImportAndDeviceWrapping({
                binding,
                caseInsensitiveRecoveryText: recovery.canonicalRecoveryText,
                untrustedExpectedCommitment: {
                    storageRootCommitment: wrongCommitment,
                },
            }),
            'CommitmentMismatch',
        );

        const recovered =
            await recoveryWorkerKernel.stageRecoveryValueImportAndDeviceWrapping(
                {
                    binding,
                    caseInsensitiveRecoveryText:
                        recovery.canonicalRecoveryText.toLowerCase(),
                    untrustedExpectedCommitment: {
                        storageRootCommitment: prepared.storageRootCommitment,
                    },
                },
            );
        expect(recovered.canonicalRecoveryText).toBe(
            recovery.canonicalRecoveryText,
        );
        expect(recovered.storageRootCommitment).toEqual(
            prepared.storageRootCommitment,
        );
        await recoveryWorkerKernel.discardStagedActionStorageRoot();

        for (let iteration = 0; iteration < 64; iteration += 1) {
            await recoveryWorkerKernel.createAndStageDeviceWrappingState({
                binding,
            });
            await recoveryWorkerKernel.discardStagedActionStorageRoot();
        }
    });
});
