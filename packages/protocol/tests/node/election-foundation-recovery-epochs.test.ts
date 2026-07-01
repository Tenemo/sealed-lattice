import { describe, expect, it } from 'vitest';

import {
    type ActionContext,
    type RecoveryEpochMapEntry,
    type RecoveryEpochUpdate,
    ceremonyId,
    contextHash,
    createBoardEvidence,
    createBoardHead,
    createBoardHeadWithObjects,
    createKeyFixture,
    createSignature,
    deriveActionContextHash,
    deriveCanonicalObjectHash,
    deriveRecoveryEpochUpdateHash,
    deriveValidatedFirstValidOrder,
    isActionCurrentForRecoveryEpoch,
    manifestPolicyHashes,
    recoveryRootKeyFixture,
    verifyRecoveryEpochUpdate,
} from './election-foundation-test-helpers';

describe('recovery epoch shells', () => {
    it('rejects mixed stale recovery and current device epochs before the old-action cutoff', () => {
        expect(
            deriveValidatedFirstValidOrder({
                requiredContextHash: contextHash,
                selectionPolicyHash: manifestPolicyHashes.firstValidPolicyHash,
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
                        objectHash: 'object-mixed-epoch',
                        objectType: 'TargetFinalityRecord',
                        boardSequence: 9,
                        boardPosition: 0,
                        signerIdentity: 'participant-1',
                        recoveryEpoch: 0,
                        deviceEpoch: 1,
                        actionSequence: 0,
                        contextHash,
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
        const recoveryHead1 = createBoardHead(1, recoveryGenesisHead.headHash);
        const recoveryHead2 = createBoardHead(2, recoveryHead1.headHash);
        const recoveryHead3 = createBoardHead(3, recoveryHead2.headHash);
        const recoveryContextHead = createBoardHead(4, recoveryHead3.headHash);
        const newSigningKeyFixture = createKeyFixture(
            'participant:participant-1:new-signing',
        );
        const payload = {
            objectType: 'RecoveryEpochUpdate',
            objectVersion: 1,
            ceremonyId,
            signerIdentity: 'participant-1',
            recoveryRootPublicKeyHash: recoveryRootKeyFixture.publicKeyHash,
            recoveryPolicyHash: manifestPolicyHashes.recoveryPolicyHash,
            previousRecoveryEpoch: 0,
            newRecoveryEpoch: 1,
            previousDeviceEpoch: 0,
            newDeviceEpoch: 1,
            oldActionCutoffBoardSequence: 5,
            boardHeadHash: recoveryContextHead.headHash,
            newSigningPublicKeyHash: newSigningKeyFixture.publicKeyHash,
            restoredEncryptedBallotStateCommitment: deriveCanonicalObjectHash({
                objectType: 'ChallengeDomainHash',
                payload: { encryptedBallotState: 'restored' },
                purpose: 'fixture-restored-encrypted-ballot-state-root-v1',
            }),
            newTrusteeSetupCommitment: deriveCanonicalObjectHash({
                objectType: 'CollectivePublicKeyRoot',
                trusteeSetup: 'new',
            }),
        } satisfies Omit<
            RecoveryEpochUpdate,
            'recoveryEpochUpdateHash' | 'signature'
        >;
        const recoveryEpochUpdateHash = deriveRecoveryEpochUpdateHash(payload);
        const update: RecoveryEpochUpdate = {
            ...payload,
            recoveryEpochUpdateHash,
            signature: createSignature(
                'RecoveryEpochUpdate',
                'RecoveryRoot',
                'participant-1',
                recoveryRootKeyFixture.publicKeyHash,
                recoveryEpochUpdateHash,
                { boardHeadHash: payload.boardHeadHash },
            ),
        };
        const { head: recoveryUpdateHead, inclusionProofs } =
            createBoardHeadWithObjects(5, recoveryContextHead.headHash, [
                {
                    objectType: 'RecoveryEpochUpdate',
                    objectHash: recoveryEpochUpdateHash,
                    boardPosition: 0,
                },
            ]);
        const recoveryUpdateInclusionProof = inclusionProofs[0];
        const verification = verifyRecoveryEpochUpdate({
            update,
            currentEntry,
            expectedRecoveryRootPublicKeyHash:
                recoveryRootKeyFixture.publicKeyHash,
            expectedRecoveryPolicyHash: manifestPolicyHashes.recoveryPolicyHash,
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

        expect(verification.isValid).toBe(true);
        expect(verification.updatedEntry).toMatchObject({
            currentRecoveryEpoch: 1,
            currentDeviceEpoch: 1,
        });
        const {
            head: delayedRecoveryUpdateHead,
            inclusionProofs: delayedRecoveryUpdateProofs,
        } = createBoardHeadWithObjects(6, recoveryUpdateHead.headHash, [
            {
                objectType: 'RecoveryEpochUpdate',
                objectHash: recoveryEpochUpdateHash,
                boardPosition: 0,
            },
        ]);
        const delayedRecoveryUpdateResult = verifyRecoveryEpochUpdate({
            update,
            currentEntry,
            expectedRecoveryRootPublicKeyHash:
                recoveryRootKeyFixture.publicKeyHash,
            expectedRecoveryPolicyHash: manifestPolicyHashes.recoveryPolicyHash,
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

        expect(delayedRecoveryUpdateResult.isValid).toBe(false);
        expect(delayedRecoveryUpdateResult.acceptedHashes).toEqual([]);
        expect(delayedRecoveryUpdateResult.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'RecoveryUpdateInvalid' }),
            ]),
        );
        const conflictingPayload = {
            ...payload,
            newSigningPublicKeyHash: createKeyFixture(
                'participant:participant-1:different-new-signing',
            ).publicKeyHash,
        };
        const conflictingRecoveryEpochUpdateHash =
            deriveRecoveryEpochUpdateHash(conflictingPayload);
        const conflictingUpdate: RecoveryEpochUpdate = {
            ...conflictingPayload,
            recoveryEpochUpdateHash: conflictingRecoveryEpochUpdateHash,
            signature: createSignature(
                'RecoveryEpochUpdate',
                'RecoveryRoot',
                'participant-1',
                recoveryRootKeyFixture.publicKeyHash,
                conflictingRecoveryEpochUpdateHash,
                { boardHeadHash: payload.boardHeadHash },
            ),
        };

        expect(
            verifyRecoveryEpochUpdate({
                update,
                currentEntry,
                expectedRecoveryRootPublicKeyHash:
                    recoveryRootKeyFixture.publicKeyHash,
                expectedRecoveryPolicyHash:
                    manifestPolicyHashes.recoveryPolicyHash,
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
                expectedRecoveryRootPublicKeyHash: createKeyFixture(
                    'recovery-root:wrong',
                ).publicKeyHash,
                expectedRecoveryPolicyHash:
                    manifestPolicyHashes.recoveryPolicyHash,
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
            recoveryPolicyHash: deriveCanonicalObjectHash({
                objectType: 'ChallengeDomainHash',
                payload: { policy: 'wrong-recovery-policy' },
                purpose: 'fixture-recovery-policy-v1',
            }),
        };
        const wrongRecoveryPolicyUpdateHash = deriveRecoveryEpochUpdateHash(
            wrongRecoveryPolicyPayload,
        );
        const wrongRecoveryPolicyUpdate: RecoveryEpochUpdate = {
            ...wrongRecoveryPolicyPayload,
            recoveryEpochUpdateHash: wrongRecoveryPolicyUpdateHash,
            signature: createSignature(
                'RecoveryEpochUpdate',
                'RecoveryRoot',
                'participant-1',
                recoveryRootKeyFixture.publicKeyHash,
                wrongRecoveryPolicyUpdateHash,
                { boardHeadHash: payload.boardHeadHash },
            ),
        };
        const {
            head: wrongPolicyUpdateHead,
            inclusionProofs: wrongPolicyProofs,
        } = createBoardHeadWithObjects(5, recoveryContextHead.headHash, [
            {
                objectType: 'RecoveryEpochUpdate',
                objectHash: wrongRecoveryPolicyUpdateHash,
                boardPosition: 0,
            },
        ]);

        expect(
            verifyRecoveryEpochUpdate({
                update: wrongRecoveryPolicyUpdate,
                currentEntry,
                expectedRecoveryRootPublicKeyHash:
                    recoveryRootKeyFixture.publicKeyHash,
                expectedRecoveryPolicyHash:
                    manifestPolicyHashes.recoveryPolicyHash,
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
        const wrongCeremonyRecoveryUpdateHash =
            deriveRecoveryEpochUpdateHash(wrongCeremonyPayload);
        const wrongCeremonyUpdate: RecoveryEpochUpdate = {
            ...wrongCeremonyPayload,
            recoveryEpochUpdateHash: wrongCeremonyRecoveryUpdateHash,
            signature: createSignature(
                'RecoveryEpochUpdate',
                'RecoveryRoot',
                'participant-1',
                recoveryRootKeyFixture.publicKeyHash,
                wrongCeremonyRecoveryUpdateHash,
                {
                    boardHeadHash: payload.boardHeadHash,
                    ceremonyId: 'ceremony-other',
                },
            ),
        };
        const {
            head: wrongCeremonyUpdateHead,
            inclusionProofs: wrongCeremonyProofs,
        } = createBoardHeadWithObjects(5, recoveryContextHead.headHash, [
            {
                objectType: 'RecoveryEpochUpdate',
                objectHash: wrongCeremonyRecoveryUpdateHash,
                boardPosition: 0,
            },
        ]);

        expect(
            verifyRecoveryEpochUpdate({
                update: wrongCeremonyUpdate,
                currentEntry,
                expectedRecoveryRootPublicKeyHash:
                    recoveryRootKeyFixture.publicKeyHash,
                expectedRecoveryPolicyHash:
                    manifestPolicyHashes.recoveryPolicyHash,
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
            electionManifestHash: deriveCanonicalObjectHash({
                objectType: 'ElectionManifestHash',
                manifest: 'main',
            }),
            signerIdentity: 'participant-1',
            boardHeadHash: payload.boardHeadHash,
            boardSequence: 6,
            recoveryEpoch: 0,
            deviceEpoch: 0,
            actionSequence: 1,
            recoveryPolicyHash: manifestPolicyHashes.recoveryPolicyHash,
            acceptedRecoveryEpochUpdateHash: recoveryEpochUpdateHash,
            rosterExternalAcceptanceHash: deriveCanonicalObjectHash({
                objectType: 'RosterExternalAcceptanceHash',
                participant: 'participant-1',
                roster: 'main',
            }),
            contextHash,
        };
        const staleActionContext: ActionContext = {
            ...staleActionPayload,
            actionContextHash: deriveActionContextHash(staleActionPayload),
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

        const wrongRosterActionResult = isActionCurrentForRecoveryEpoch({
            actionContext: staleActionContext,
            recoveryEpochState: currentEntry,
            expectedRosterExternalAcceptanceHash: deriveCanonicalObjectHash({
                objectType: 'RosterExternalAcceptanceHash',
                participant: 'participant-1',
                roster: 'different',
            }),
        });

        expect(wrongRosterActionResult.isValid).toBe(false);
        expect(wrongRosterActionResult.acceptedHashes).toEqual([]);
        expect(wrongRosterActionResult.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'RosterExternalAcceptanceInvalid',
                }),
            ]),
        );
    });
});
