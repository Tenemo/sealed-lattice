import { describe, expect, it } from 'vitest';

import {
    closeRecordElectionManifestHash,
    createAcceptedTargetScenario,
    createDecryptionShare,
    createLocalReplayRecord,
    createTargetAcceptedRecord,
    createVotingCloseScenario,
    signDecryptionShare,
    signLocalReplayRecord,
    signTargetAcceptedRecord,
} from './election-foundation-cast-close-target-acceptance/fixtures.js';
import {
    createBoardEvidence,
    createBoardHeadWithObjects,
    deriveProtocolHash,
    getParticipantSigningPublicKeyHash,
    organizerPublicKeyHash,
    verifyCloseRecordShell,
    verifyLocalReplayRecordShell,
    verifyTargetAcceptedRecordShell,
    verifyTopKDecryptionShareShell,
} from './election-foundation-test-helpers';
describe('close record shells', () => {
    it('accepts voting close records bound to the successor close head', () => {
        const scenario = createVotingCloseScenario();

        expect(
            verifyCloseRecordShell({
                boardEvidence: scenario.boardEvidence,
                closeRecord: scenario.closeRecord,
                closeRecordInclusionProof: scenario.closeRecordInclusionProof,
                expectedElectionManifestHash: closeRecordElectionManifestHash,
                expectedOrganizerIdentity: 'organizer',
                expectedOrganizerPublicKeyHash: organizerPublicKeyHash,
            }),
        ).toMatchObject({
            ok: true,
            closeRecordHash: scenario.closeRecord.closeRecordHash,
            postVotingClosedContextHash:
                scenario.closeRecord.postVotingClosedContextHash,
        });
    });

    it('rejects close records whose closed head is not the predecessor of the close publication head', () => {
        const scenario = createVotingCloseScenario({
            useGenesisAsClosedHead: true,
        });

        const result = verifyCloseRecordShell({
            boardEvidence: scenario.boardEvidence,
            closeRecord: scenario.closeRecord,
            closeRecordInclusionProof: scenario.closeRecordInclusionProof,
            expectedElectionManifestHash: closeRecordElectionManifestHash,
            expectedOrganizerIdentity: 'organizer',
            expectedOrganizerPublicKeyHash: organizerPublicKeyHash,
        });

        expect(result.ok).toBe(false);
        expect(result.acceptedHashes).toEqual([]);
        expect(result.closeRecordHash).toBeUndefined();
        expect(result.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'CloseRecordInvalid' }),
            ]),
        );
    });
});

describe('target acceptance and local replay shells', () => {
    it('accepts a target only with exact finality and mandatory evaluation proof evidence', () => {
        const scenario = createAcceptedTargetScenario();

        expect(scenario.targetFinalityVerification.ok).toBe(true);
        expect(scenario.targetAcceptedRecordVerification).toMatchObject({
            ok: true,
            targetAcceptedRecordHash:
                scenario.targetAcceptedRecord.targetAcceptedRecordHash,
            targetFinalityRecordHash:
                scenario.targetFinalityRecord.targetFinalityRecordHash,
        });

        expect(
            verifyTargetAcceptedRecordShell({
                ...scenario,
                evaluationProofRecord: {
                    ...scenario.evaluationProofRecord,
                    targetCiphertextHash: deriveProtocolHash('CiphertextRoot', {
                        target: 'wrong',
                    }),
                },
                expectedOrganizerPublicKeyHash: organizerPublicKeyHash,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'TargetAcceptedRecordInvalid',
                }),
            ]),
        );

        const unsignedMisplacedTargetAcceptedRecord =
            createTargetAcceptedRecord(
                scenario.targetFinalityRecord,
                scenario.evaluationProofRecord,
            );
        const {
            head: misplacedAcceptedHead,
            inclusionProofs: misplacedAcceptedProofs,
        } = createBoardHeadWithObjects(
            3,
            scenario.evaluationProofHead.headHash,
            [
                {
                    objectType: 'TargetAcceptedRecord',
                    objectHash:
                        unsignedMisplacedTargetAcceptedRecord.targetAcceptedRecordHash,
                    boardPosition:
                        unsignedMisplacedTargetAcceptedRecord.boardPosition + 1,
                },
            ],
        );
        const misplacedTargetAcceptedRecord = signTargetAcceptedRecord(
            unsignedMisplacedTargetAcceptedRecord,
            misplacedAcceptedHead.headHash,
        );
        const misplacedTargetResult = verifyTargetAcceptedRecordShell({
            boardEvidence: createBoardEvidence([
                scenario.head0,
                scenario.head1,
                scenario.evaluationProofHead,
                misplacedAcceptedHead,
            ]),
            targetAcceptedRecord: misplacedTargetAcceptedRecord,
            targetAcceptedRecordInclusionProof: misplacedAcceptedProofs[0],
            targetFinalityRecord: scenario.targetFinalityRecord,
            targetFinalityVerification: scenario.targetFinalityVerification,
            evaluationProofRecord: scenario.evaluationProofRecord,
            expectedOrganizerPublicKeyHash: organizerPublicKeyHash,
        });

        expect(misplacedTargetResult.ok).toBe(false);
        expect(misplacedTargetResult.acceptedHashes).toEqual([]);
        expect(misplacedTargetResult.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'InclusionProofInvalid' }),
            ]),
        );
    });

    it('keeps user-requested local replay additive and non-authorizing', () => {
        const scenario = createAcceptedTargetScenario();
        const localReplayRecord = createLocalReplayRecord(
            scenario.targetFinalityRecord,
            scenario.evaluationProofRecord,
        );
        const { head: replayHead, inclusionProofs } =
            createBoardHeadWithObjects(4, scenario.acceptedHead.headHash, [
                {
                    objectType: 'LocalReplayRecord',
                    objectHash: localReplayRecord.localReplayRecordHash,
                    boardPosition: 0,
                },
            ]);
        const signedLocalReplayRecord = signLocalReplayRecord(
            localReplayRecord,
            replayHead.headHash,
        );
        const boardEvidence = createBoardEvidence([
            scenario.head0,
            scenario.head1,
            scenario.evaluationProofHead,
            scenario.acceptedHead,
            replayHead,
        ]);
        const localReplayInclusionProof = inclusionProofs[0];

        expect(
            verifyLocalReplayRecordShell({
                boardEvidence,
                record: signedLocalReplayRecord,
                recordInclusionProof: localReplayInclusionProof,
                targetFinalityRecord: scenario.targetFinalityRecord,
                targetFinalityVerification: scenario.targetFinalityVerification,
                evaluationProofRecord: scenario.evaluationProofRecord,
                expectedSignerPublicKeyHash:
                    getParticipantSigningPublicKeyHash('participant-1'),
            }),
        ).toMatchObject({
            ok: true,
            localReplayRecordHash: localReplayRecord.localReplayRecordHash,
            targetFinalityRecordHash:
                scenario.targetFinalityRecord.targetFinalityRecordHash,
        });

        expect(
            verifyLocalReplayRecordShell({
                boardEvidence,
                record: {
                    ...signedLocalReplayRecord,
                    evaluationProofRecordHash: deriveProtocolHash(
                        'EvaluationProofRecordHash',
                        { proof: 'wrong' },
                    ),
                },
                recordInclusionProof: localReplayInclusionProof,
                targetFinalityRecord: scenario.targetFinalityRecord,
                targetFinalityVerification: scenario.targetFinalityVerification,
                evaluationProofRecord: scenario.evaluationProofRecord,
                expectedSignerPublicKeyHash:
                    getParticipantSigningPublicKeyHash('participant-1'),
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'LocalReplayRecordInvalid' }),
            ]),
        );
    });

    it('requires target-bound decryption shares to bind accepted target and profile Hashes', () => {
        const scenario = createAcceptedTargetScenario();
        const decryptionShare = createDecryptionShare(
            scenario.targetAcceptedRecord,
        );
        const { head: shareHead, inclusionProofs } = createBoardHeadWithObjects(
            4,
            scenario.acceptedHead.headHash,
            [
                {
                    objectType: 'TopKDecryptionShare',
                    objectHash: decryptionShare.topKDecryptionShareHash,
                    boardPosition: decryptionShare.boardPosition,
                },
            ],
        );
        const signedDecryptionShare = signDecryptionShare(
            decryptionShare,
            shareHead.headHash,
        );
        const boardEvidence = createBoardEvidence([
            scenario.head0,
            scenario.head1,
            scenario.evaluationProofHead,
            scenario.acceptedHead,
            shareHead,
        ]);

        expect(
            verifyTopKDecryptionShareShell({
                boardEvidence,
                decryptionShare: signedDecryptionShare,
                decryptionShareInclusionProof: inclusionProofs[0],
                targetAcceptedRecord: scenario.targetAcceptedRecord,
                targetAcceptedRecordVerification:
                    scenario.targetAcceptedRecordVerification,
                expectedTrusteePublicKeyHash:
                    getParticipantSigningPublicKeyHash('participant-1'),
            }),
        ).toMatchObject({
            ok: true,
            topKDecryptionShareHash: decryptionShare.topKDecryptionShareHash,
            targetAcceptedRecordHash:
                scenario.targetAcceptedRecord.targetAcceptedRecordHash,
        });

        expect(
            verifyTopKDecryptionShareShell({
                boardEvidence,
                decryptionShare: {
                    ...signedDecryptionShare,
                    cpadProfileHash: deriveProtocolHash('CPADProfileHash', {
                        profile: 'wrong',
                    }),
                },
                decryptionShareInclusionProof: inclusionProofs[0],
                targetAcceptedRecord: scenario.targetAcceptedRecord,
                targetAcceptedRecordVerification:
                    scenario.targetAcceptedRecordVerification,
                expectedTrusteePublicKeyHash:
                    getParticipantSigningPublicKeyHash('participant-1'),
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'DecryptionShareInvalid' }),
            ]),
        );

        expect(
            verifyTopKDecryptionShareShell({
                boardEvidence,
                decryptionShare: {
                    ...signedDecryptionShare,
                    targetDecryptionCiphertextHash: deriveProtocolHash(
                        'TargetDecryptionCiphertextHash',
                        { target: 'wrong' },
                    ),
                },
                decryptionShareInclusionProof: inclusionProofs[0],
                targetAcceptedRecord: scenario.targetAcceptedRecord,
                targetAcceptedRecordVerification:
                    scenario.targetAcceptedRecordVerification,
                expectedTrusteePublicKeyHash:
                    getParticipantSigningPublicKeyHash('participant-1'),
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'DecryptionShareInvalid' }),
            ]),
        );

        expect(
            verifyTopKDecryptionShareShell({
                boardEvidence,
                decryptionShare: {
                    ...signedDecryptionShare,
                    thresholdShareVerificationKeyRoot: deriveProtocolHash(
                        'ThresholdShareVerificationKeyRoot',
                        { trustee: 'wrong' },
                    ),
                },
                decryptionShareInclusionProof: inclusionProofs[0],
                targetAcceptedRecord: scenario.targetAcceptedRecord,
                targetAcceptedRecordVerification:
                    scenario.targetAcceptedRecordVerification,
                expectedTrusteePublicKeyHash:
                    getParticipantSigningPublicKeyHash('participant-1'),
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'DecryptionShareInvalid' }),
            ]),
        );

        const {
            head: misplacedShareHead,
            inclusionProofs: misplacedShareProofs,
        } = createBoardHeadWithObjects(4, scenario.acceptedHead.headHash, [
            {
                objectType: 'TopKDecryptionShare',
                objectHash: decryptionShare.topKDecryptionShareHash,
                boardPosition: decryptionShare.boardPosition + 1,
            },
        ]);
        const misplacedSignedDecryptionShare = signDecryptionShare(
            decryptionShare,
            misplacedShareHead.headHash,
        );
        const misplacedShareResult = verifyTopKDecryptionShareShell({
            boardEvidence: createBoardEvidence([
                scenario.head0,
                scenario.head1,
                scenario.evaluationProofHead,
                scenario.acceptedHead,
                misplacedShareHead,
            ]),
            decryptionShare: misplacedSignedDecryptionShare,
            decryptionShareInclusionProof: misplacedShareProofs[0],
            targetAcceptedRecord: scenario.targetAcceptedRecord,
            targetAcceptedRecordVerification:
                scenario.targetAcceptedRecordVerification,
            expectedTrusteePublicKeyHash:
                getParticipantSigningPublicKeyHash('participant-1'),
        });

        expect(misplacedShareResult.ok).toBe(false);
        expect(misplacedShareResult.acceptedHashes).toEqual([]);
        expect(misplacedShareResult.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'InclusionProofInvalid' }),
            ]),
        );

        expect(
            verifyTopKDecryptionShareShell({
                boardEvidence,
                decryptionShare: {
                    ...signedDecryptionShare,
                    recoveryEpoch: -1,
                },
                decryptionShareInclusionProof: inclusionProofs[0],
                targetAcceptedRecord: scenario.targetAcceptedRecord,
                targetAcceptedRecordVerification:
                    scenario.targetAcceptedRecordVerification,
                expectedTrusteePublicKeyHash:
                    getParticipantSigningPublicKeyHash('participant-1'),
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'DecryptionShareInvalid' }),
            ]),
        );
    });
});
