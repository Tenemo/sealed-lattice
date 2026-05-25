import { describe, expect, it } from 'vitest';

import {
    type ActionContext,
    type RecoveryEpochMapEntry,
    type RecoveryEpochUpdate,
    ceremonyId,
    contextDigest,
    createBoardEvidence,
    createBoardHead,
    createBoardHeadWithObjects,
    createKeyFixture,
    createSignature,
    deriveActionContextDigest,
    deriveProtocolDigest,
    deriveRecoveryEpochUpdateDigest,
    deriveValidatedFirstValidOrder,
    isActionCurrentForRecoveryEpoch,
    manifestPolicyDigests,
    recoveryRootKeyFixture,
    verifyRecoveryEpochUpdate,
} from './election-foundation-test-helpers';

describe('recovery epoch shells', () => {
    it('rejects mixed stale recovery and current device epochs before the old-action cutoff', () => {
        expect(
            deriveValidatedFirstValidOrder({
                requiredContextDigest: contextDigest,
                selectionPolicyDigest:
                    manifestPolicyDigests.firstValidPolicyDigest,
                expectedSelectionPolicyDigest:
                    manifestPolicyDigests.firstValidPolicyDigest,
                currentRecoveryEpochMap: {
                    'participant-1': {
                        signerIdentity: 'participant-1',
                        currentRecoveryEpoch: 1,
                        currentDeviceEpoch: 1,
                        oldActionCutoffBoardSequence: 10,
                    },
                },
                objects: [
                    {
                        objectDigest: 'object-mixed-epoch',
                        objectType: 'TargetFinalityRecord',
                        boardSequence: 9,
                        boardPosition: 0,
                        signerIdentity: 'participant-1',
                        recoveryEpoch: 0,
                        deviceEpoch: 1,
                        actionSequence: 0,
                        contextDigest,
                        isByteIdenticalRetransmission: false,
                    },
                ],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'StaleRecoveryEpoch' }),
            ]),
        );
    });

    it('verifies recovery updates and refuses stale action contexts', () => {
        const currentEntry: RecoveryEpochMapEntry = {
            signerIdentity: 'participant-1',
            currentRecoveryEpoch: 0,
            currentDeviceEpoch: 0,
        };
        const recoveryGenesisHead = createBoardHead(0, null);
        const recoveryHead1 = createBoardHead(
            1,
            recoveryGenesisHead.headDigest,
        );
        const recoveryHead2 = createBoardHead(2, recoveryHead1.headDigest);
        const recoveryHead3 = createBoardHead(3, recoveryHead2.headDigest);
        const recoveryContextHead = createBoardHead(
            4,
            recoveryHead3.headDigest,
        );
        const newSigningKeyFixture = createKeyFixture(
            'participant:participant-1:new-signing',
        );
        const payload = {
            objectType: 'RecoveryEpochUpdate',
            objectVersion: 1,
            ceremonyId,
            signerIdentity: 'participant-1',
            recoveryRootPublicKeyDigest: recoveryRootKeyFixture.publicKeyDigest,
            recoveryPolicyDigest: manifestPolicyDigests.recoveryPolicyDigest,
            previousRecoveryEpoch: 0,
            newRecoveryEpoch: 1,
            previousDeviceEpoch: 0,
            newDeviceEpoch: 1,
            oldActionCutoffBoardSequence: 5,
            boardHeadDigest: recoveryContextHead.headDigest,
            newSigningPublicKeyDigest: newSigningKeyFixture.publicKeyDigest,
            restoredFrozenReceiverStateCommitment: deriveProtocolDigest(
                'EncryptedEnvelopeRoot',
                { receiverState: 'restored' },
            ),
            newTrusteeSetupCommitment: deriveProtocolDigest(
                'CollectivePublicKeyRoot',
                { trusteeSetup: 'new' },
            ),
        } satisfies Omit<
            RecoveryEpochUpdate,
            'recoveryEpochUpdateDigest' | 'signature'
        >;
        const recoveryEpochUpdateDigest =
            deriveRecoveryEpochUpdateDigest(payload);
        const update: RecoveryEpochUpdate = {
            ...payload,
            recoveryEpochUpdateDigest,
            signature: createSignature(
                'RecoveryEpochUpdate',
                'RecoveryRoot',
                'participant-1',
                recoveryRootKeyFixture.publicKeyDigest,
                recoveryEpochUpdateDigest,
                { boardHeadDigest: payload.boardHeadDigest },
            ),
        };
        const { head: recoveryUpdateHead, inclusionProofs } =
            createBoardHeadWithObjects(5, recoveryContextHead.headDigest, [
                {
                    objectType: 'RecoveryEpochUpdate',
                    objectDigest: recoveryEpochUpdateDigest,
                    boardPosition: 0,
                },
            ]);
        const recoveryUpdateInclusionProof = inclusionProofs[0];
        const verification = verifyRecoveryEpochUpdate({
            update,
            currentEntry,
            expectedRecoveryRootPublicKeyDigest:
                recoveryRootKeyFixture.publicKeyDigest,
            expectedRecoveryPolicyDigest:
                manifestPolicyDigests.recoveryPolicyDigest,
            boardEvidence: createBoardEvidence([
                recoveryGenesisHead,
                recoveryHead1,
                recoveryHead2,
                recoveryHead3,
                recoveryContextHead,
                recoveryUpdateHead,
            ]),
            updateInclusionProof: recoveryUpdateInclusionProof,
        });

        expect(verification.ok).toBe(true);
        expect(verification.updatedEntry).toMatchObject({
            currentRecoveryEpoch: 1,
            currentDeviceEpoch: 1,
        });
        const {
            head: delayedRecoveryUpdateHead,
            inclusionProofs: delayedRecoveryUpdateProofs,
        } = createBoardHeadWithObjects(6, recoveryUpdateHead.headDigest, [
            {
                objectType: 'RecoveryEpochUpdate',
                objectDigest: recoveryEpochUpdateDigest,
                boardPosition: 0,
            },
        ]);
        const delayedRecoveryUpdateResult = verifyRecoveryEpochUpdate({
            update,
            currentEntry,
            expectedRecoveryRootPublicKeyDigest:
                recoveryRootKeyFixture.publicKeyDigest,
            expectedRecoveryPolicyDigest:
                manifestPolicyDigests.recoveryPolicyDigest,
            boardEvidence: createBoardEvidence([
                recoveryGenesisHead,
                recoveryHead1,
                recoveryHead2,
                recoveryHead3,
                recoveryContextHead,
                recoveryUpdateHead,
                delayedRecoveryUpdateHead,
            ]),
            updateInclusionProof: delayedRecoveryUpdateProofs[0],
        });

        expect(delayedRecoveryUpdateResult.ok).toBe(false);
        expect(delayedRecoveryUpdateResult.acceptedDigests).toEqual([]);
        expect(delayedRecoveryUpdateResult.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'RecoveryUpdateInvalid' }),
            ]),
        );
        const conflictingPayload = {
            ...payload,
            newSigningPublicKeyDigest: createKeyFixture(
                'participant:participant-1:different-new-signing',
            ).publicKeyDigest,
        };
        const conflictingRecoveryEpochUpdateDigest =
            deriveRecoveryEpochUpdateDigest(conflictingPayload);
        const conflictingUpdate: RecoveryEpochUpdate = {
            ...conflictingPayload,
            recoveryEpochUpdateDigest: conflictingRecoveryEpochUpdateDigest,
            signature: createSignature(
                'RecoveryEpochUpdate',
                'RecoveryRoot',
                'participant-1',
                recoveryRootKeyFixture.publicKeyDigest,
                conflictingRecoveryEpochUpdateDigest,
                { boardHeadDigest: payload.boardHeadDigest },
            ),
        };

        expect(
            verifyRecoveryEpochUpdate({
                update,
                currentEntry,
                expectedRecoveryRootPublicKeyDigest:
                    recoveryRootKeyFixture.publicKeyDigest,
                expectedRecoveryPolicyDigest:
                    manifestPolicyDigests.recoveryPolicyDigest,
                boardEvidence: createBoardEvidence([
                    recoveryGenesisHead,
                    recoveryHead1,
                    recoveryHead2,
                    recoveryHead3,
                    recoveryContextHead,
                    recoveryUpdateHead,
                ]),
                updateInclusionProof: recoveryUpdateInclusionProof,
                conflictingUpdates: [conflictingUpdate],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'RecoveryUpdateConflict' }),
            ]),
        );
        expect(
            verifyRecoveryEpochUpdate({
                update,
                currentEntry,
                expectedRecoveryRootPublicKeyDigest: createKeyFixture(
                    'recovery-root:wrong',
                ).publicKeyDigest,
                expectedRecoveryPolicyDigest:
                    manifestPolicyDigests.recoveryPolicyDigest,
                boardEvidence: createBoardEvidence([
                    recoveryGenesisHead,
                    recoveryHead1,
                    recoveryHead2,
                    recoveryHead3,
                    recoveryContextHead,
                    recoveryUpdateHead,
                ]),
                updateInclusionProof: recoveryUpdateInclusionProof,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongPublicKey' }),
            ]),
        );
        const wrongRecoveryPolicyPayload = {
            ...payload,
            recoveryPolicyDigest: deriveProtocolDigest('RecoveryPolicyDigest', {
                policy: 'wrong-recovery-policy',
            }),
        };
        const wrongRecoveryPolicyUpdateDigest = deriveRecoveryEpochUpdateDigest(
            wrongRecoveryPolicyPayload,
        );
        const wrongRecoveryPolicyUpdate: RecoveryEpochUpdate = {
            ...wrongRecoveryPolicyPayload,
            recoveryEpochUpdateDigest: wrongRecoveryPolicyUpdateDigest,
            signature: createSignature(
                'RecoveryEpochUpdate',
                'RecoveryRoot',
                'participant-1',
                recoveryRootKeyFixture.publicKeyDigest,
                wrongRecoveryPolicyUpdateDigest,
                { boardHeadDigest: payload.boardHeadDigest },
            ),
        };
        const {
            head: wrongPolicyUpdateHead,
            inclusionProofs: wrongPolicyProofs,
        } = createBoardHeadWithObjects(5, recoveryContextHead.headDigest, [
            {
                objectType: 'RecoveryEpochUpdate',
                objectDigest: wrongRecoveryPolicyUpdateDigest,
                boardPosition: 0,
            },
        ]);

        expect(
            verifyRecoveryEpochUpdate({
                update: wrongRecoveryPolicyUpdate,
                currentEntry,
                expectedRecoveryRootPublicKeyDigest:
                    recoveryRootKeyFixture.publicKeyDigest,
                expectedRecoveryPolicyDigest:
                    manifestPolicyDigests.recoveryPolicyDigest,
                boardEvidence: createBoardEvidence([
                    recoveryGenesisHead,
                    recoveryHead1,
                    recoveryHead2,
                    recoveryHead3,
                    recoveryContextHead,
                    wrongPolicyUpdateHead,
                ]),
                updateInclusionProof: wrongPolicyProofs[0],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'RecoveryUpdateInvalid' }),
            ]),
        );
        const wrongCeremonyPayload = {
            ...payload,
            ceremonyId: 'ceremony-other',
        };
        const wrongCeremonyRecoveryUpdateDigest =
            deriveRecoveryEpochUpdateDigest(wrongCeremonyPayload);
        const wrongCeremonyUpdate: RecoveryEpochUpdate = {
            ...wrongCeremonyPayload,
            recoveryEpochUpdateDigest: wrongCeremonyRecoveryUpdateDigest,
            signature: createSignature(
                'RecoveryEpochUpdate',
                'RecoveryRoot',
                'participant-1',
                recoveryRootKeyFixture.publicKeyDigest,
                wrongCeremonyRecoveryUpdateDigest,
                {
                    boardHeadDigest: payload.boardHeadDigest,
                    ceremonyId: 'ceremony-other',
                },
            ),
        };
        const {
            head: wrongCeremonyUpdateHead,
            inclusionProofs: wrongCeremonyProofs,
        } = createBoardHeadWithObjects(5, recoveryContextHead.headDigest, [
            {
                objectType: 'RecoveryEpochUpdate',
                objectDigest: wrongCeremonyRecoveryUpdateDigest,
                boardPosition: 0,
            },
        ]);

        expect(
            verifyRecoveryEpochUpdate({
                update: wrongCeremonyUpdate,
                currentEntry,
                expectedRecoveryRootPublicKeyDigest:
                    recoveryRootKeyFixture.publicKeyDigest,
                expectedRecoveryPolicyDigest:
                    manifestPolicyDigests.recoveryPolicyDigest,
                boardEvidence: createBoardEvidence([
                    recoveryGenesisHead,
                    recoveryHead1,
                    recoveryHead2,
                    recoveryHead3,
                    recoveryContextHead,
                    wrongCeremonyUpdateHead,
                ]),
                updateInclusionProof: wrongCeremonyProofs[0],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongCeremony' }),
            ]),
        );

        const staleActionPayload = {
            ceremonyId,
            electionManifestDigest: deriveProtocolDigest(
                'ElectionManifestDigest',
                { manifest: 'main' },
            ),
            signerIdentity: 'participant-1',
            boardHeadDigest: payload.boardHeadDigest,
            boardSequence: 6,
            recoveryEpoch: 0,
            deviceEpoch: 0,
            actionSequence: 1,
            recoveryPolicyDigest: manifestPolicyDigests.recoveryPolicyDigest,
            acceptedRecoveryEpochUpdateDigest: recoveryEpochUpdateDigest,
            rosterExternalAcceptanceDigest: deriveProtocolDigest(
                'RosterExternalAcceptanceDigest',
                { participant: 'participant-1', roster: 'main' },
            ),
            contextDigest,
        };
        const staleActionContext: ActionContext = {
            ...staleActionPayload,
            actionContextDigest: deriveActionContextDigest(staleActionPayload),
        };

        expect(
            isActionCurrentForRecoveryEpoch({
                actionContext: staleActionContext,
                recoveryEpochState: verification.updatedEntry ?? currentEntry,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'StaleRecoveryEpoch' }),
            ]),
        );

        expect(
            isActionCurrentForRecoveryEpoch({
                actionContext: staleActionContext,
                recoveryEpochState: currentEntry,
                expectedRosterExternalAcceptanceDigest: deriveProtocolDigest(
                    'RosterExternalAcceptanceDigest',
                    { participant: 'participant-1', roster: 'different' },
                ),
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'RosterExternalAcceptanceInvalid',
                }),
            ]),
        );
    });
});
