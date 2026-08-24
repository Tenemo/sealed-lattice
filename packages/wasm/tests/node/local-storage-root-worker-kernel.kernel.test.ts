import {
    BrowserActionStorageCustodyError,
    foundationProfile,
    stateCapabilityKinds,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import { createBrowserLocalSigningOperations } from '#packages/crypto/tests/support/browser-local-key-operations';
import {
    createCanonicalCarrierMailboxKeyPairFixtures,
    createCanonicalCarrierSigningKeyPairFixtures,
} from '#packages/crypto/tests/support/canonical-carrier-signature-fixtures';
import {
    createWasmBrowserActionStorageWorkerKernel,
    loadFreshTranscriptCoreKernel,
} from '#packages/wasm/src/index';
import {
    closeWorkerActionRandomness,
    createAndSealWorkerActionRandomness,
    openClosedWorkerSetupMailboxRandomness,
    openSealedWorkerActionRandomness,
    withClosedWorkerProductionOperationAuthority,
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

const expectCustodyErrorCode = async (
    operation: Promise<unknown>,
    code: BrowserActionStorageCustodyError['code'],
): Promise<void> => {
    await expect(operation).rejects.toMatchObject({
        code,
        name: 'BrowserActionStorageCustodyError',
    });
};

const openProductionOperationAuthorityFixture = async () => {
    const baseStateVector = createStateVerifierTestVector();
    const kernel = await loadFreshTranscriptCoreKernel();
    const workerKernel = createWasmBrowserActionStorageWorkerKernel({ kernel });
    await workerKernel.createAndStageDeviceWrappingState({
        binding: {
            actionContextHash: baseStateVector.actionContextHash,
            ceremonyContextHash: baseStateVector.ceremonyContextHash,
            participantId: baseStateVector.subjectParticipantIdentity,
            suiteId: baseStateVector.suiteIdentifier,
        },
    });
    await workerKernel.commitStagedActionStorageRoot();
    const actionRandomness = await createAndSealWorkerActionRandomness(
        workerKernel,
        { recordVersion: 0n },
    );
    const stateVector = createStateVerifierTestVector({
        setupActionRandomnessAuthorizationHash:
            deriveSetupActionRandomnessAuthorization(
                baseStateVector,
                actionRandomness.actionRandomnessCommitment,
            ),
    });
    const stateVerifierSession =
        await workerKernel.openActionStateVerifierSession({
            canonicalRosterBytes: stateVector.canonicalRosterBytes,
        });
    if (!stateVerifierSession.isValid) {
        throw new Error('State-verifier session did not open.');
    }
    const reservationVector = stateVector.reservationOnly.find(
        ({ capabilityKind }) =>
            capabilityKind === stateCapabilityKinds.setupActionRandomnessRoot,
    );
    if (reservationVector === undefined) {
        throw new Error('Missing action-randomness reservation vector.');
    }
    const stateReservation =
        await workerKernel.verifyActionRandomnessReservation({
            actionRandomnessSessionIdentifier:
                actionRandomness.actionRandomnessSessionIdentifier,
            canonicalReservationIntentCarrier:
                reservationVector.certifiedIntent.canonicalIntentCarrier,
            canonicalStateCertificate:
                reservationVector.certifiedIntent.canonicalStateCertificate,
            stateVerifierSessionIdentifier: stateVerifierSession.value,
        });
    if (!stateReservation.isValid) {
        throw new Error('Action-randomness reservation did not verify.');
    }

    return Object.freeze({
        close: async (): Promise<void> => {
            await workerKernel.closeActionStateVerifierSession(
                stateVerifierSession.value,
            );
            await closeWorkerActionRandomness(
                workerKernel,
                actionRandomness.actionRandomnessSessionIdentifier,
            );
            await workerKernel.destroyActiveActionStorageRoot();
        },
        identifiers: Object.freeze({
            actionRandomnessSessionIdentifier:
                actionRandomness.actionRandomnessSessionIdentifier,
            stateReservationIdentifier: stateReservation.value,
            stateVerifierSessionIdentifier: stateVerifierSession.value,
        }),
        kernel,
        workerKernel,
    });
};

describe('Local storage-root real-WASM worker kernel', () => {
    it('observes and types a deferred kernel-load failure before first use', async () => {
        const workerKernel = createWasmBrowserActionStorageWorkerKernel({
            kernel: Promise.reject(new Error('synthetic kernel-load failure')),
        });

        await Promise.resolve();
        await Promise.resolve();

        await expectCustodyErrorCode(
            workerKernel.destroyActiveActionStorageRoot(),
            'Unavailable',
        );
    });

    it('prepares one complete worker-owned foundation initialization batch', async () => {
        const vector = createStateVerifierTestVector();
        const workerKernel = createWasmBrowserActionStorageWorkerKernel({
            kernel: loadFreshTranscriptCoreKernel(),
        });
        await workerKernel.createAndStageDeviceWrappingState({
            binding: {
                actionContextHash: vector.actionContextHash,
                ceremonyContextHash: vector.ceremonyContextHash,
                participantId: vector.subjectParticipantIdentity,
                suiteId: vector.suiteIdentifier,
            },
        });
        await workerKernel.commitStagedActionStorageRoot();
        const prepared =
            await workerKernel.prepareBrowserFoundationInitialization({
                actionRandomnessRecordContext: { recordVersion: 0n },
                orderedWitnessBindings: Array.from(
                    { length: foundationProfile.participantCount - 1 },
                    (_unused, witnessIndex) => ({
                        subjectParticipantIdentity: createBytes(
                            64,
                            101 + witnessIndex,
                        ),
                        witnessParticipantIdentity:
                            vector.subjectParticipantIdentity,
                    }),
                ),
                runtimeBuildManifestHash: createBytes(64, 71),
            });

        expect(prepared.witnessStateRecords).toHaveLength(
            foundationProfile.participantCount - 1,
        );
        expect(
            new Set(
                prepared.witnessStateRecords.map((record) =>
                    Buffer.from(record.localRecordIdentifier).toString('hex'),
                ),
            ).size,
        ).toBe(foundationProfile.participantCount - 1);
        await workerKernel.closeActionRandomness(
            prepared.actionRandomness.actionRandomnessSessionIdentifier,
        );
        await workerKernel.destroyActiveActionStorageRoot();
    });

    it('keeps exact production-operation authorities opaque, pinned, and callback-scoped', async () => {
        const fixture = await openProductionOperationAuthorityFixture();
        let useAuthorityAfterCompletion: (() => unknown) | undefined;
        let readKernelAfterCompletion: (() => unknown) | undefined;
        try {
            await withClosedWorkerProductionOperationAuthority(
                fixture.workerKernel,
                fixture.identifiers,
                async (authority) => {
                    expect(Object.keys(authority)).toEqual([]);
                    expect(JSON.stringify(authority)).toBe('{}');
                    useAuthorityAfterCompletion = () =>
                        authority.withExactKernelAuthorization(() => undefined);
                    await authority.withExactKernelAuthorization(
                        async (authorization) => {
                            expect(Object.keys(authorization)).toEqual([]);
                            expect(JSON.stringify(authorization)).toBe('{}');
                            expect(authorization.kernel).toBe(fixture.kernel);
                            expect(
                                authorization.actionRandomnessContext.memory,
                            ).toBe(
                                authorization.stateReservationCapabilityMemory,
                            );
                            readKernelAfterCompletion = () =>
                                authorization.kernel;
                            await Promise.resolve();
                            expect(authorization.kernel).toBe(fixture.kernel);
                        },
                    );
                },
            );

            expect(useAuthorityAfterCompletion).toBeDefined();
            expect(readKernelAfterCompletion).toBeDefined();
            expect(() => useAuthorityAfterCompletion?.()).toThrow(
                BrowserActionStorageCustodyError,
            );
            expect(() => readKernelAfterCompletion?.()).toThrow(
                BrowserActionStorageCustodyError,
            );

            let useAuthorityAfterFailure: (() => unknown) | undefined;
            await expect(
                withClosedWorkerProductionOperationAuthority(
                    fixture.workerKernel,
                    fixture.identifiers,
                    (authority) => {
                        useAuthorityAfterFailure = () =>
                            authority.withExactKernelAuthorization(
                                () => undefined,
                            );
                        throw new Error(
                            'Synthetic production-operation failure.',
                        );
                    },
                ),
            ).rejects.toThrow('Synthetic production-operation failure.');
            expect(useAuthorityAfterFailure).toBeDefined();
            expect(() => useAuthorityAfterFailure?.()).toThrow(
                BrowserActionStorageCustodyError,
            );

            const returningExactKernelOperation: () => void = () => 41;
            await expectCustodyErrorCode(
                withClosedWorkerProductionOperationAuthority(
                    fixture.workerKernel,
                    fixture.identifiers,
                    async (authority) => {
                        await authority.withExactKernelAuthorization(
                            returningExactKernelOperation,
                        );
                    },
                ),
                'InvalidInput',
            );
            const returningProductionOperation: () => void = () => 47;
            await expectCustodyErrorCode(
                withClosedWorkerProductionOperationAuthority(
                    fixture.workerKernel,
                    fixture.identifiers,
                    returningProductionOperation,
                ),
                'InvalidInput',
            );

            let subsequentCallbackEntered = false;
            await withClosedWorkerProductionOperationAuthority(
                fixture.workerKernel,
                fixture.identifiers,
                async (authority) => {
                    await authority.withExactKernelAuthorization(() => {
                        subsequentCallbackEntered = true;
                    });
                },
            );
            expect(subsequentCallbackEntered).toBe(true);
        } finally {
            await fixture.close();
        }
    });

    it('produces a signed setup intent from worker-owned randomness and state authority', async () => {
        const fixture = await openProductionOperationAuthorityFixture();
        const signingKeyPairs = createCanonicalCarrierSigningKeyPairFixtures(
            foundationProfile.participantCount,
        );
        const mailboxKeyPairs = createCanonicalCarrierMailboxKeyPairFixtures(
            foundationProfile.participantCount,
        );
        const sourceSigningKeyPair = signingKeyPairs[0];
        const sourceMailboxKeyPair = mailboxKeyPairs[0];
        if (
            sourceSigningKeyPair === undefined ||
            sourceMailboxKeyPair === undefined
        ) {
            throw new Error('The deterministic source key pairs are missing.');
        }
        const signingOperations =
            createBrowserLocalSigningOperations(sourceSigningKeyPair);
        let setupRandomness:
            | Awaited<ReturnType<typeof openClosedWorkerSetupMailboxRandomness>>
            | undefined;
        try {
            setupRandomness = await openClosedWorkerSetupMailboxRandomness(
                fixture.workerKernel,
                {
                    actionRandomnessSessionIdentifier:
                        fixture.identifiers.actionRandomnessSessionIdentifier,
                    signing: signingOperations,
                    sourceMailboxEncapsulationKey:
                        sourceMailboxKeyPair.publicKey,
                    stateReservationIdentifier:
                        fixture.identifiers.stateReservationIdentifier,
                },
            );

            const canonicalSetupIntentCarrier =
                setupRandomness.produceSetupIntentCarrier();
            expect(canonicalSetupIntentCarrier.byteLength).toBeGreaterThan(
                3_309,
            );

            setupRandomness.revoke();
            expect(() => setupRandomness?.produceSetupIntentCarrier()).toThrow(
                BrowserActionStorageCustodyError,
            );
        } finally {
            setupRandomness?.revoke();
            signingOperations.revoke();
            for (const signingKeyPair of signingKeyPairs) {
                signingKeyPair.secretKey.fill(0);
            }
            for (const mailboxKeyPair of mailboxKeyPairs) {
                mailboxKeyPair.secretKey.fill(0);
            }
            await fixture.close();
        }
    });

    it('refuses cross-kernel production-operation identifiers before callback entry', async () => {
        const sourceFixture = await openProductionOperationAuthorityFixture();
        const otherFixture = await openProductionOperationAuthorityFixture();
        try {
            let crossKernelCallbackEntryCount = 0;
            await expectCustodyErrorCode(
                withClosedWorkerProductionOperationAuthority(
                    sourceFixture.workerKernel,
                    {
                        actionRandomnessSessionIdentifier:
                            sourceFixture.identifiers
                                .actionRandomnessSessionIdentifier,
                        stateReservationIdentifier:
                            otherFixture.identifiers.stateReservationIdentifier,
                        stateVerifierSessionIdentifier:
                            otherFixture.identifiers
                                .stateVerifierSessionIdentifier,
                    },
                    () => {
                        crossKernelCallbackEntryCount += 1;
                    },
                ),
                'InvalidState',
            );
            await expectCustodyErrorCode(
                withClosedWorkerProductionOperationAuthority(
                    sourceFixture.workerKernel,
                    {
                        ...sourceFixture.identifiers,
                        actionRandomnessSessionIdentifier:
                            otherFixture.identifiers
                                .actionRandomnessSessionIdentifier,
                    },
                    () => {
                        crossKernelCallbackEntryCount += 1;
                    },
                ),
                'InvalidState',
            );

            expect(crossKernelCallbackEntryCount).toBe(0);
        } finally {
            await sourceFixture.close();
            await otherFixture.close();
        }
    });

    it('seals and recovers action randomness without exposing its root plaintext', async () => {
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
        const preparedDeviceWrappingState =
            await workerKernel.createAndStageDeviceWrappingState({
                binding: actionBinding,
            });
        await workerKernel.commitStagedActionStorageRoot();
        const recordContext = {
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
        if (!targetReservation.isValid) {
            throw new Error('Proof-attempt reservations did not verify.');
        }
        const targetAttemptInput = {
            actionRandomnessSessionIdentifier:
                created.actionRandomnessSessionIdentifier,
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
        await expectCustodyErrorCode(
            createAndSealWorkerActionRandomness(workerKernel, recordContext),
            'Conflict',
        );
        await closeWorkerActionRandomness(
            workerKernel,
            created.actionRandomnessSessionIdentifier,
        );
        await workerKernel.closeActionStateVerifierSession(
            openedStateSession.value,
        );
        await workerKernel.destroyActiveActionStorageRoot();

        const tamperedEnvelope = created.canonicalEnvelope.slice();
        tamperedEnvelope[tamperedEnvelope.byteLength - 1] ^= 1;
        const tamperedOpeningWorkerKernel =
            createWasmBrowserActionStorageWorkerKernel({
                kernel: loadFreshTranscriptCoreKernel(),
            });
        await tamperedOpeningWorkerKernel.stageDeviceWrappingStateOpen({
            binding: actionBinding,
            untrustedExpectedCommitment: {
                storageRootCommitment:
                    preparedDeviceWrappingState.storageRootCommitment,
            },
            state: preparedDeviceWrappingState,
        });
        await tamperedOpeningWorkerKernel.commitStagedActionStorageRoot();
        await expectCustodyErrorCode(
            openSealedWorkerActionRandomness(tamperedOpeningWorkerKernel, {
                ...recordContext,
                actionRandomnessCommitment: created.actionRandomnessCommitment,
                canonicalEnvelope: tamperedEnvelope,
            }),
            'RecordAuthenticationFailed',
        );
        await expectCustodyErrorCode(
            openSealedWorkerActionRandomness(tamperedOpeningWorkerKernel, {
                ...recordContext,
                actionRandomnessCommitment: created.actionRandomnessCommitment,
                canonicalEnvelope: created.canonicalEnvelope,
            }),
            'Conflict',
        );
        await tamperedOpeningWorkerKernel.destroyActiveActionStorageRoot();

        const recoveredWorkerKernel =
            createWasmBrowserActionStorageWorkerKernel({
                kernel: loadFreshTranscriptCoreKernel(),
            });
        await recoveredWorkerKernel.stageDeviceWrappingStateOpen({
            binding: actionBinding,
            untrustedExpectedCommitment: {
                storageRootCommitment:
                    preparedDeviceWrappingState.storageRootCommitment,
            },
            state: preparedDeviceWrappingState,
        });
        await recoveredWorkerKernel.commitStagedActionStorageRoot();
        const reopened = await openSealedWorkerActionRandomness(
            recoveredWorkerKernel,
            {
                ...recordContext,
                actionRandomnessCommitment: created.actionRandomnessCommitment,
                canonicalEnvelope: created.canonicalEnvelope,
            },
        );
        expect(reopened.actionRandomnessCommitment).toEqual(
            created.actionRandomnessCommitment,
        );
        await expectCustodyErrorCode(
            openSealedWorkerActionRandomness(recoveredWorkerKernel, {
                ...recordContext,
                actionRandomnessCommitment: created.actionRandomnessCommitment,
                canonicalEnvelope: created.canonicalEnvelope,
            }),
            'Conflict',
        );
        const recoveredStateSession =
            await recoveredWorkerKernel.openActionStateVerifierSession({
                canonicalRosterBytes: stateVector.canonicalRosterBytes,
            });
        if (!recoveredStateSession.isValid) {
            throw new Error('Recovered state-verifier session did not open.');
        }
        const recoveredTargetReservation =
            await recoveredWorkerKernel.verifyActionStateReservation({
                canonicalReservationIntentCarrier:
                    stateVector.reservation.canonicalIntentCarrier,
                canonicalStateCertificate:
                    stateVector.reservation.canonicalStateCertificate,
                capabilityKind: stateCapabilityKinds.targetRelease,
                expectedAuthorizationHash: stateVector.authorizationHash,
                stateVerifierSessionIdentifier: recoveredStateSession.value,
                subjectParticipantIdentity:
                    stateVector.subjectParticipantIdentity,
            });
        if (!recoveredTargetReservation.isValid) {
            throw new Error(
                'Recovered proof-attempt reservation did not verify.',
            );
        }
        const recoveredTargetAttemptInput = {
            actionRandomnessSessionIdentifier:
                reopened.actionRandomnessSessionIdentifier,
            rosterPosition: 0,
            stateReservationIdentifier: recoveredTargetReservation.value,
        } as const;
        expect(
            await recoveredWorkerKernel.deriveTargetReleaseAttempt(
                recoveredTargetAttemptInput,
            ),
        ).toEqual(
            await recoveredWorkerKernel.deriveTargetReleaseAttempt(
                recoveredTargetAttemptInput,
            ),
        );
        await closeWorkerActionRandomness(
            recoveredWorkerKernel,
            reopened.actionRandomnessSessionIdentifier,
        );
        await recoveredWorkerKernel.closeActionStateVerifierSession(
            recoveredStateSession.value,
        );
        await recoveredWorkerKernel.destroyActiveActionStorageRoot();
    });

    it('derives, seals, authenticates, versions, and hashes local records inside the owned kernel', async () => {
        const workerKernel = createWasmBrowserActionStorageWorkerKernel({
            kernel: loadFreshTranscriptCoreKernel(),
        });
        await workerKernel.createAndStageDeviceWrappingState({ binding });
        await workerKernel.commitStagedActionStorageRoot();

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

    it('wraps, activates, destroys, and reopens local state after a worker crash', async () => {
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
        await initialWorkerKernel.commitStagedActionStorageRoot();
        await initialWorkerKernel.destroyActiveActionStorageRoot();
        await initialWorkerKernel.destroyActiveActionStorageRoot();

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
        await replacementWorkerKernel.commitStagedActionStorageRoot();
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
            openingWorkerKernel.commitStagedActionStorageRoot(),
            'InvalidState',
        );
    });
});
