import { describe, expect, it } from 'vitest';

import {
    type CastReceipt,
    type CloseRecord,
    type EvaluationReplayAttestation,
    type TargetAcceptedRecord,
    type TargetFinalityVerification,
    type TopKDecryptionShareShell,
    ceremonyId,
    contextDigest,
    createBoardEvidence,
    createBoardHead,
    createBoardHeadWithObjects,
    createSignature,
    createTargetFinalityRecord,
    createTargetProposalHead,
    deriveCastReceiptDigest,
    deriveCloseRecordDigest,
    deriveEvaluationReplayAttestationDigest,
    derivePostVotingClosedContextDigest,
    deriveProtocolDigest,
    deriveTargetAcceptedRecordDigest,
    deriveTopKDecryptionShareDigest,
    getParticipantKeyFixture,
    organizerPublicKeyDigest,
    targetFinalityPolicy,
    verifyCastReceiptShell,
    verifyCloseRecordShell,
    verifyEvaluationReplayAttestationShell,
    verifyTargetAcceptedRecordShell,
    verifyTargetFinality,
    verifyTopKDecryptionShareShell,
    witnessPolicy,
    witnessPublicKeyDigests,
} from './election-foundation-test-helpers';

describe('cast, close, and target-phase shells', () => {
    it('verifies cast receipt and voting-close shells', () => {
        const electionManifestDigest = deriveProtocolDigest(
            'ElectionManifestDigest',
            { manifest: 'shell' },
        );
        const voterKey = getParticipantKeyFixture('participant-1');
        const head0 = createBoardHead(0, null);
        const castReceiptPayload = {
            objectType: 'CastReceipt',
            objectVersion: 1,
            ceremonyId,
            electionManifestDigest,
            voterIdentity: 'participant-1',
            ballotPackageDigest: deriveProtocolDigest('BallotPackageDigest', {
                ballot: 'participant-1',
            }),
            boardSeq: 1,
            boardPosition: 0,
            recoveryEpoch: 0,
            deviceEpoch: 0,
            contextDigest,
        } satisfies Omit<CastReceipt, 'castReceiptDigest' | 'signature'>;
        const castReceiptDigest = deriveCastReceiptDigest(castReceiptPayload);
        const { head: castHead, inclusionProofs: castInclusionProofs } =
            createBoardHeadWithObjects(1, head0.headDigest, [
                {
                    objectType: 'CastReceipt',
                    objectDigest: castReceiptDigest,
                    boardPosition: 0,
                },
            ]);
        const castReceipt: CastReceipt = {
            ...castReceiptPayload,
            castReceiptDigest,
            signature: createSignature(
                'CastReceipt',
                'Voter',
                'participant-1',
                voterKey.publicKeyDigest,
                castReceiptDigest,
                {
                    boardHeadHash: castHead.headDigest,
                    manifestHash: electionManifestDigest,
                },
            ),
        };

        expect(
            verifyCastReceiptShell({
                boardEvidence: createBoardEvidence([head0, castHead]),
                receipt: castReceipt,
                receiptInclusionProof: castInclusionProofs[0],
                expectedElectionManifestDigest: electionManifestDigest,
                expectedVoterPublicKeyDigest: voterKey.publicKeyDigest,
            }).ok,
        ).toBe(true);

        const closeRecordPayload = {
            objectType: 'CloseRecord',
            objectVersion: 1,
            ceremonyId,
            electionManifestDigest,
            closeKind: 'VotingClosed',
            closedBoardHeadDigest: castHead.headDigest,
            postVotingClosedContextDigest: null,
            boardSeq: 2,
            boardPosition: 0,
            organizerIdentity: 'organizer',
        } satisfies Omit<CloseRecord, 'closeRecordDigest' | 'signature'>;
        const closeRecordDigest = deriveCloseRecordDigest(closeRecordPayload);
        const { head: closeHead, inclusionProofs: closeInclusionProofs } =
            createBoardHeadWithObjects(2, castHead.headDigest, [
                {
                    objectType: 'CloseRecord',
                    objectDigest: closeRecordDigest,
                    boardPosition: 0,
                },
            ]);
        const postVotingClosedContextDigest =
            derivePostVotingClosedContextDigest({
                ceremonyId,
                closeRecordDigest,
                electionManifestDigest,
                votingClosedBoardHeadDigest: closeHead.headDigest,
            });
        const closeRecord: CloseRecord = {
            ...closeRecordPayload,
            postVotingClosedContextDigest,
            closeRecordDigest,
            signature: createSignature(
                'CloseRecord',
                'Organizer',
                'organizer',
                organizerPublicKeyDigest,
                closeRecordDigest,
                {
                    boardHeadHash: closeHead.headDigest,
                    manifestHash: electionManifestDigest,
                },
            ),
        };
        const closeVerification = verifyCloseRecordShell({
            boardEvidence: createBoardEvidence([head0, castHead, closeHead]),
            closeRecord,
            closeRecordInclusionProof: closeInclusionProofs[0],
            expectedElectionManifestDigest: electionManifestDigest,
            expectedOrganizerIdentity: 'organizer',
            expectedOrganizerPublicKeyDigest: organizerPublicKeyDigest,
        });

        expect(closeVerification).toMatchObject({
            ok: true,
            postVotingClosedContextDigest,
        });
        expect(
            verifyCloseRecordShell({
                boardEvidence: createBoardEvidence([
                    head0,
                    castHead,
                    closeHead,
                ]),
                closeRecord: {
                    ...closeRecord,
                    postVotingClosedContextDigest: deriveProtocolDigest(
                        'PostVotingClosedContextDigest',
                        { wrong: true },
                    ),
                },
                closeRecordInclusionProof: closeInclusionProofs[0],
                expectedElectionManifestDigest: electionManifestDigest,
                expectedOrganizerIdentity: 'organizer',
                expectedOrganizerPublicKeyDigest: organizerPublicKeyDigest,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'CloseRecordInvalid' }),
            ]),
        );
    });

    it('binds replay attestation, target acceptance, and decryption-share shells to target finality', () => {
        const electionManifestDigest = deriveProtocolDigest(
            'ElectionManifestDigest',
            { manifest: 'target-phase-shell' },
        );
        const participantKey = getParticipantKeyFixture('participant-1');
        const head0 = createBoardHead(0, null);
        const targetHead = createTargetProposalHead(1, head0.headDigest);
        const targetFinalityRecord = createTargetFinalityRecord(targetHead);
        const targetFinalityVerification = verifyTargetFinality({
            boardEvidence: createBoardEvidence([head0, targetHead]),
            record: targetFinalityRecord,
            witnessPolicy,
            targetFinalityPolicy,
            witnessPublicKeyDigests,
        });
        const replayPayload = {
            objectType: 'EvaluationReplayAttestation',
            objectVersion: 1,
            ceremonyId,
            electionManifestDigest,
            signerIdentity: 'participant-1',
            topKEvaluationRecordDigest:
                targetFinalityRecord.topKEvaluationRecordDigest,
            targetFinalityRecordDigest:
                targetFinalityRecord.targetFinalityRecordDigest,
            finalizedBoardHeadDigest:
                targetFinalityRecord.finalizedBoardHeadDigest,
            replayContextDigest: contextDigest,
            boardSeq: 2,
            boardPosition: 0,
            recoveryEpoch: 0,
            deviceEpoch: 0,
        } satisfies Omit<
            EvaluationReplayAttestation,
            'evaluationReplayAttestationDigest' | 'signature'
        >;
        const replayDigest =
            deriveEvaluationReplayAttestationDigest(replayPayload);
        const { head: replayHead, inclusionProofs: replayProofs } =
            createBoardHeadWithObjects(2, targetHead.headDigest, [
                {
                    objectType: 'EvaluationReplayAttestation',
                    objectDigest: replayDigest,
                    boardPosition: 0,
                },
            ]);
        const replayAttestation: EvaluationReplayAttestation = {
            ...replayPayload,
            evaluationReplayAttestationDigest: replayDigest,
            signature: createSignature(
                'EvaluationReplayAttestation',
                'Participant',
                'participant-1',
                participantKey.publicKeyDigest,
                replayDigest,
                {
                    boardHeadHash: replayHead.headDigest,
                    contextDigest,
                    manifestHash: electionManifestDigest,
                },
            ),
        };
        const replayVerification = verifyEvaluationReplayAttestationShell({
            boardEvidence: createBoardEvidence([head0, targetHead, replayHead]),
            attestation: replayAttestation,
            attestationInclusionProof: replayProofs[0],
            targetFinalityRecord,
            targetFinalityVerification,
            expectedSignerPublicKeyDigest: participantKey.publicKeyDigest,
        });

        expect(replayVerification.ok).toBe(true);
        expect(
            verifyEvaluationReplayAttestationShell({
                boardEvidence: createBoardEvidence([
                    head0,
                    targetHead,
                    replayHead,
                ]),
                attestation: replayAttestation,
                attestationInclusionProof: replayProofs[0],
                targetFinalityRecord,
                targetFinalityVerification: {
                    ...targetFinalityVerification,
                    ok: false,
                    acceptedDigests: [],
                    targetFinalityRecordDigest: undefined,
                    finalizedBoardHeadDigest: undefined,
                } satisfies TargetFinalityVerification,
                expectedSignerPublicKeyDigest: participantKey.publicKeyDigest,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'TargetPhaseAuthorizationFailure',
                }),
            ]),
        );

        const targetAcceptedPayload = {
            objectType: 'TargetAcceptedRecord',
            objectVersion: 1,
            ceremonyId,
            electionManifestDigest,
            targetPhase: targetFinalityRecord.targetPhase,
            topKEvaluationRecordDigest:
                targetFinalityRecord.topKEvaluationRecordDigest,
            targetFinalityRecordDigest:
                targetFinalityRecord.targetFinalityRecordDigest,
            replayAttestationDigests: [replayDigest],
            optionalEvaluationProofRoot: null,
            boardSeq: 3,
            boardPosition: 0,
            organizerIdentity: 'organizer',
        } satisfies Omit<
            TargetAcceptedRecord,
            'targetAcceptedRecordDigest' | 'signature'
        >;
        const targetAcceptedRecordDigest = deriveTargetAcceptedRecordDigest(
            targetAcceptedPayload,
        );
        const { head: acceptedHead, inclusionProofs: acceptedProofs } =
            createBoardHeadWithObjects(3, replayHead.headDigest, [
                {
                    objectType: 'TargetAcceptedRecord',
                    objectDigest: targetAcceptedRecordDigest,
                    boardPosition: 0,
                },
            ]);
        const targetAcceptedRecord: TargetAcceptedRecord = {
            ...targetAcceptedPayload,
            targetAcceptedRecordDigest,
            signature: createSignature(
                'TargetAcceptedRecord',
                'Organizer',
                'organizer',
                organizerPublicKeyDigest,
                targetAcceptedRecordDigest,
                {
                    boardHeadHash: acceptedHead.headDigest,
                    manifestHash: electionManifestDigest,
                },
            ),
        };
        const targetAcceptedVerification = verifyTargetAcceptedRecordShell({
            boardEvidence: createBoardEvidence([
                head0,
                targetHead,
                replayHead,
                acceptedHead,
            ]),
            targetAcceptedRecord,
            targetAcceptedRecordInclusionProof: acceptedProofs[0],
            targetFinalityRecord,
            targetFinalityVerification,
            acceptedReplayAttestationDigests: [
                replayVerification.evaluationReplayAttestationDigest ?? '',
            ],
            expectedOrganizerPublicKeyDigest: organizerPublicKeyDigest,
        });

        expect(targetAcceptedVerification.ok).toBe(true);

        const decryptionSharePayload = {
            objectType: 'TopKDecryptionShare',
            objectVersion: 1,
            ceremonyId,
            electionManifestDigest,
            trusteeIdentity: 'participant-1',
            targetAcceptedRecordDigest,
            targetFinalityRecordDigest:
                targetFinalityRecord.targetFinalityRecordDigest,
            topKEvaluationRecordDigest:
                targetFinalityRecord.topKEvaluationRecordDigest,
            boardSeq: 4,
            boardPosition: 0,
            recoveryEpoch: 0,
            deviceEpoch: 0,
            shareRoot: deriveProtocolDigest('TopKDecryptionShareDigest', {
                share: 'placeholder',
            }),
        } satisfies Omit<
            TopKDecryptionShareShell,
            'topKDecryptionShareDigest' | 'signature'
        >;
        const decryptionShareDigest = deriveTopKDecryptionShareDigest(
            decryptionSharePayload,
        );
        const { head: shareHead, inclusionProofs: shareProofs } =
            createBoardHeadWithObjects(4, acceptedHead.headDigest, [
                {
                    objectType: 'TopKDecryptionShare',
                    objectDigest: decryptionShareDigest,
                    boardPosition: 0,
                },
            ]);
        const decryptionShare: TopKDecryptionShareShell = {
            ...decryptionSharePayload,
            topKDecryptionShareDigest: decryptionShareDigest,
            signature: createSignature(
                'TopKDecryptionShare',
                'Trustee',
                'participant-1',
                participantKey.publicKeyDigest,
                decryptionShareDigest,
                {
                    boardHeadHash: shareHead.headDigest,
                    manifestHash: electionManifestDigest,
                },
            ),
        };

        expect(
            verifyTopKDecryptionShareShell({
                boardEvidence: createBoardEvidence([
                    head0,
                    targetHead,
                    replayHead,
                    acceptedHead,
                    shareHead,
                ]),
                decryptionShare,
                decryptionShareInclusionProof: shareProofs[0],
                targetAcceptedRecord,
                targetAcceptedRecordVerification: targetAcceptedVerification,
                expectedTrusteePublicKeyDigest: participantKey.publicKeyDigest,
            }).ok,
        ).toBe(true);

        const wrongFinalitySharePayload = {
            ...decryptionSharePayload,
            targetFinalityRecordDigest: deriveProtocolDigest(
                'TargetFinalityRecordDigest',
                { wrong: true },
            ),
        };
        const wrongFinalityShareDigest = deriveTopKDecryptionShareDigest(
            wrongFinalitySharePayload,
        );
        const { head: wrongShareHead, inclusionProofs: wrongShareProofs } =
            createBoardHeadWithObjects(4, acceptedHead.headDigest, [
                {
                    objectType: 'TopKDecryptionShare',
                    objectDigest: wrongFinalityShareDigest,
                    boardPosition: 0,
                },
            ]);

        expect(
            verifyTopKDecryptionShareShell({
                boardEvidence: createBoardEvidence([
                    head0,
                    targetHead,
                    replayHead,
                    acceptedHead,
                    wrongShareHead,
                ]),
                decryptionShare: {
                    ...wrongFinalitySharePayload,
                    topKDecryptionShareDigest: wrongFinalityShareDigest,
                    signature: createSignature(
                        'TopKDecryptionShare',
                        'Trustee',
                        'participant-1',
                        participantKey.publicKeyDigest,
                        wrongFinalityShareDigest,
                        {
                            boardHeadHash: wrongShareHead.headDigest,
                            manifestHash: electionManifestDigest,
                        },
                    ),
                },
                decryptionShareInclusionProof: wrongShareProofs[0],
                targetAcceptedRecord,
                targetAcceptedRecordVerification: targetAcceptedVerification,
                expectedTrusteePublicKeyDigest: participantKey.publicKeyDigest,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'DecryptionShareInvalid' }),
            ]),
        );
    });
});
