import { describe, expect, it } from 'vitest';

import {
    closeRecordElectionManifestDigest,
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
    deriveProtocolDigest,
    getParticipantSigningPublicKeyDigest,
    organizerPublicKeyDigest,
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
                expectedElectionManifestDigest:
                    closeRecordElectionManifestDigest,
                expectedOrganizerIdentity: 'organizer',
                expectedOrganizerPublicKeyDigest: organizerPublicKeyDigest,
            }),
        ).toMatchObject({
            ok: true,
            closeRecordDigest: scenario.closeRecord.closeRecordDigest,
            postVotingClosedContextDigest:
                scenario.closeRecord.postVotingClosedContextDigest,
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
            expectedElectionManifestDigest: closeRecordElectionManifestDigest,
            expectedOrganizerIdentity: 'organizer',
            expectedOrganizerPublicKeyDigest: organizerPublicKeyDigest,
        });

        expect(result.ok).toBe(false);
        expect(result.acceptedDigests).toEqual([]);
        expect(result.closeRecordDigest).toBeUndefined();
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
            targetAcceptedRecordDigest:
                scenario.targetAcceptedRecord.targetAcceptedRecordDigest,
            targetFinalityRecordDigest:
                scenario.targetFinalityRecord.targetFinalityRecordDigest,
        });

        expect(
            verifyTargetAcceptedRecordShell({
                ...scenario,
                evaluationProofRecord: {
                    ...scenario.evaluationProofRecord,
                    targetCiphertextDigest: deriveProtocolDigest(
                        'CiphertextRoot',
                        {
                            target: 'wrong',
                        },
                    ),
                },
                expectedOrganizerPublicKeyDigest: organizerPublicKeyDigest,
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
            scenario.evaluationProofHead.headDigest,
            [
                {
                    objectType: 'TargetAcceptedRecord',
                    objectDigest:
                        unsignedMisplacedTargetAcceptedRecord.targetAcceptedRecordDigest,
                    boardPosition:
                        unsignedMisplacedTargetAcceptedRecord.boardPosition + 1,
                },
            ],
        );
        const misplacedTargetAcceptedRecord = signTargetAcceptedRecord(
            unsignedMisplacedTargetAcceptedRecord,
            misplacedAcceptedHead.headDigest,
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
            expectedOrganizerPublicKeyDigest: organizerPublicKeyDigest,
        });

        expect(misplacedTargetResult.ok).toBe(false);
        expect(misplacedTargetResult.acceptedDigests).toEqual([]);
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
            createBoardHeadWithObjects(4, scenario.acceptedHead.headDigest, [
                {
                    objectType: 'LocalReplayRecord',
                    objectDigest: localReplayRecord.localReplayRecordDigest,
                    boardPosition: 0,
                },
            ]);
        const signedLocalReplayRecord = signLocalReplayRecord(
            localReplayRecord,
            replayHead.headDigest,
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
                expectedSignerPublicKeyDigest:
                    getParticipantSigningPublicKeyDigest('participant-1'),
            }),
        ).toMatchObject({
            ok: true,
            localReplayRecordDigest: localReplayRecord.localReplayRecordDigest,
            targetFinalityRecordDigest:
                scenario.targetFinalityRecord.targetFinalityRecordDigest,
        });

        expect(
            verifyLocalReplayRecordShell({
                boardEvidence,
                record: {
                    ...signedLocalReplayRecord,
                    evaluationProofRecordDigest: deriveProtocolDigest(
                        'EvaluationProofRecordDigest',
                        { proof: 'wrong' },
                    ),
                },
                recordInclusionProof: localReplayInclusionProof,
                targetFinalityRecord: scenario.targetFinalityRecord,
                targetFinalityVerification: scenario.targetFinalityVerification,
                evaluationProofRecord: scenario.evaluationProofRecord,
                expectedSignerPublicKeyDigest:
                    getParticipantSigningPublicKeyDigest('participant-1'),
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'LocalReplayRecordInvalid' }),
            ]),
        );
    });

    it('requires target-bound decryption shares to bind accepted target and profile digests', () => {
        const scenario = createAcceptedTargetScenario();
        const decryptionShare = createDecryptionShare(
            scenario.targetAcceptedRecord,
        );
        const { head: shareHead, inclusionProofs } = createBoardHeadWithObjects(
            4,
            scenario.acceptedHead.headDigest,
            [
                {
                    objectType: 'TopKDecryptionShare',
                    objectDigest: decryptionShare.topKDecryptionShareDigest,
                    boardPosition: decryptionShare.boardPosition,
                },
            ],
        );
        const signedDecryptionShare = signDecryptionShare(
            decryptionShare,
            shareHead.headDigest,
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
                expectedTrusteePublicKeyDigest:
                    getParticipantSigningPublicKeyDigest('participant-1'),
            }),
        ).toMatchObject({
            ok: true,
            topKDecryptionShareDigest:
                decryptionShare.topKDecryptionShareDigest,
            targetAcceptedRecordDigest:
                scenario.targetAcceptedRecord.targetAcceptedRecordDigest,
        });

        expect(
            verifyTopKDecryptionShareShell({
                boardEvidence,
                decryptionShare: {
                    ...signedDecryptionShare,
                    cpadProfileDigest: deriveProtocolDigest(
                        'CPADProfileDigest',
                        { profile: 'wrong' },
                    ),
                },
                decryptionShareInclusionProof: inclusionProofs[0],
                targetAcceptedRecord: scenario.targetAcceptedRecord,
                targetAcceptedRecordVerification:
                    scenario.targetAcceptedRecordVerification,
                expectedTrusteePublicKeyDigest:
                    getParticipantSigningPublicKeyDigest('participant-1'),
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
                    targetDecryptionCiphertextDigest: deriveProtocolDigest(
                        'TargetDecryptionCiphertextDigest',
                        { target: 'wrong' },
                    ),
                },
                decryptionShareInclusionProof: inclusionProofs[0],
                targetAcceptedRecord: scenario.targetAcceptedRecord,
                targetAcceptedRecordVerification:
                    scenario.targetAcceptedRecordVerification,
                expectedTrusteePublicKeyDigest:
                    getParticipantSigningPublicKeyDigest('participant-1'),
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
                    thresholdShareVerificationKeyRoot: deriveProtocolDigest(
                        'ThresholdShareVerificationKeyRoot',
                        { trustee: 'wrong' },
                    ),
                },
                decryptionShareInclusionProof: inclusionProofs[0],
                targetAcceptedRecord: scenario.targetAcceptedRecord,
                targetAcceptedRecordVerification:
                    scenario.targetAcceptedRecordVerification,
                expectedTrusteePublicKeyDigest:
                    getParticipantSigningPublicKeyDigest('participant-1'),
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'DecryptionShareInvalid' }),
            ]),
        );

        const {
            head: misplacedShareHead,
            inclusionProofs: misplacedShareProofs,
        } = createBoardHeadWithObjects(4, scenario.acceptedHead.headDigest, [
            {
                objectType: 'TopKDecryptionShare',
                objectDigest: decryptionShare.topKDecryptionShareDigest,
                boardPosition: decryptionShare.boardPosition + 1,
            },
        ]);
        const misplacedSignedDecryptionShare = signDecryptionShare(
            decryptionShare,
            misplacedShareHead.headDigest,
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
            expectedTrusteePublicKeyDigest:
                getParticipantSigningPublicKeyDigest('participant-1'),
        });

        expect(misplacedShareResult.ok).toBe(false);
        expect(misplacedShareResult.acceptedDigests).toEqual([]);
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
                expectedTrusteePublicKeyDigest:
                    getParticipantSigningPublicKeyDigest('participant-1'),
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'DecryptionShareInvalid' }),
            ]),
        );
    });
});
