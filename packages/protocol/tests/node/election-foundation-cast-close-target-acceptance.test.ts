import type {
    CloseRecord,
    EvaluationProofRecord,
    LocalReplayRecord,
    TargetAcceptedRecord,
    TopKDecryptionShareShell,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    ceremonyId,
    createBoardEvidence,
    createBoardHead,
    createBoardHeadWithObjects,
    createSignature,
    createTargetFinalityRecord,
    createTargetProposalHead,
    deriveCloseRecordDigest,
    deriveLocalReplayRecordDigest,
    derivePostVotingClosedContextDigest,
    deriveProtocolDigest,
    deriveTargetAcceptedRecordDigest,
    deriveTopKDecryptionShareDigest,
    getParticipantSigningPublicKeyDigest,
    manifestOpaqueBindings,
    organizerPublicKeyDigest,
    verifyCloseRecordShell,
    verifyLocalReplayRecordShell,
    verifyTargetAcceptedRecordShell,
    verifyTargetFinality,
    verifyTopKDecryptionShareShell,
    witnessPolicy,
    targetFinalityPolicy,
    witnessPublicKeyDigests,
} from './election-foundation-test-helpers';

const closeRecordElectionManifestDigest = deriveProtocolDigest(
    'ElectionManifestDigest',
    { manifest: 'close-record-shell' },
);

const createVotingCloseScenario = (input?: {
    readonly useGenesisAsClosedHead?: boolean;
}): {
    readonly boardEvidence: ReturnType<typeof createBoardEvidence>;
    readonly closeRecord: CloseRecord;
    readonly closeRecordInclusionProof: ReturnType<
        typeof createBoardHeadWithObjects
    >['inclusionProofs'][number];
    readonly closedHead: ReturnType<typeof createBoardHead>;
    readonly closeHead: ReturnType<typeof createBoardHead>;
    readonly genesisHead: ReturnType<typeof createBoardHead>;
} => {
    const genesisHead = createBoardHead(0, null);
    const closedHead = createBoardHead(1, genesisHead.headDigest);
    const closedBoardHeadDigest = input?.useGenesisAsClosedHead
        ? genesisHead.headDigest
        : closedHead.headDigest;
    const closeRecordPayload = {
        objectType: 'CloseRecord',
        objectVersion: 1,
        ceremonyId,
        electionManifestDigest: closeRecordElectionManifestDigest,
        closeKind: 'VotingClosed',
        closedBoardHeadDigest,
        boardSequence: 2,
        boardPosition: 0,
        organizerIdentity: 'organizer',
    } satisfies Omit<
        CloseRecord,
        'closeRecordDigest' | 'postVotingClosedContextDigest' | 'signature'
    >;
    const closeRecordDigest = deriveCloseRecordDigest(closeRecordPayload);
    const { head: closeHead, inclusionProofs } = createBoardHeadWithObjects(
        2,
        closedHead.headDigest,
        [
            {
                objectType: 'CloseRecord',
                objectDigest: closeRecordDigest,
                boardPosition: closeRecordPayload.boardPosition,
            },
        ],
    );
    const postVotingClosedContextDigest = derivePostVotingClosedContextDigest({
        ceremonyId,
        closeRecordDigest,
        electionManifestDigest: closeRecordElectionManifestDigest,
        votingClosedBoardHeadDigest: closeHead.headDigest,
    });
    const closeRecord: CloseRecord = {
        ...closeRecordPayload,
        closeRecordDigest,
        postVotingClosedContextDigest,
        signature: createSignature(
            'CloseRecord',
            'Organizer',
            'organizer',
            organizerPublicKeyDigest,
            closeRecordDigest,
            {
                boardHeadDigest: closeHead.headDigest,
                contextDigest: postVotingClosedContextDigest,
                manifestDigest: closeRecordElectionManifestDigest,
            },
        ),
    };

    return {
        boardEvidence: createBoardEvidence([
            genesisHead,
            closedHead,
            closeHead,
        ]),
        closeRecord,
        closeRecordInclusionProof: inclusionProofs[0],
        closedHead,
        closeHead,
        genesisHead,
    };
};

const deriveEvaluationProofRecordDigest = (
    proofRecord: Omit<EvaluationProofRecord, 'evaluationProofRecordDigest'>,
): string =>
    deriveProtocolDigest('EvaluationProofRecordDigest', {
        targetCiphertextDigest: proofRecord.targetCiphertextDigest,
        topKCiphertextDigest: proofRecord.topKCiphertextDigest,
        ceremonyId: proofRecord.ceremonyId,
        electionManifestDigest: proofRecord.electionManifestDigest,
        evaluationContextDigest: proofRecord.evaluationContextDigest,
        evaluationProofProfileDigest: proofRecord.evaluationProofProfileDigest,
        objectType: proofRecord.objectType,
        objectVersion: proofRecord.objectVersion,
        proofRoot: proofRecord.proofRoot,
        publicSlotMaskDigest: proofRecord.publicSlotMaskDigest,
        targetFinalityRecordDigest: proofRecord.targetFinalityRecordDigest,
        targetLayoutDigest: proofRecord.targetLayoutDigest,
        targetProposalDigest: proofRecord.targetProposalDigest,
        topKEvaluationRecordDigest: proofRecord.topKEvaluationRecordDigest,
    });

const createEvaluationProofRecord = (
    targetFinalityRecord: ReturnType<typeof createTargetFinalityRecord>,
): EvaluationProofRecord => {
    const checkpoint = targetFinalityRecord.targetFinalityCheckpoint;
    const payload = {
        objectType: 'EvaluationProofRecord',
        objectVersion: 1,
        ceremonyId,
        electionManifestDigest: checkpoint.electionManifestDigest,
        targetProposalDigest: targetFinalityRecord.targetProposalDigest,
        topKEvaluationRecordDigest: checkpoint.topKEvaluationRecordDigest,
        targetFinalityRecordDigest:
            targetFinalityRecord.targetFinalityRecordDigest,
        evaluationProofProfileDigest: checkpoint.evaluationProofProfileDigest,
        evaluationContextDigest: checkpoint.evaluationContextDigest,
        topKCiphertextDigest: checkpoint.topKCiphertextDigest,
        publicSlotMaskDigest: checkpoint.publicSlotMaskDigest,
        targetCiphertextDigest: checkpoint.targetCiphertextDigest,
        targetLayoutDigest: checkpoint.targetLayoutDigest,
        proofRoot: deriveProtocolDigest('EvaluationProofRecordDigest', {
            proof: 'mandatory-pq-evaluation-proof',
        }),
        boardSequence: 2,
        boardPosition: 0,
    } as const;

    return {
        ...payload,
        evaluationProofRecordDigest: deriveEvaluationProofRecordDigest(payload),
    };
};

const createTargetAcceptedRecord = (
    targetFinalityRecord: ReturnType<typeof createTargetFinalityRecord>,
    evaluationProofRecord: EvaluationProofRecord,
): TargetAcceptedRecord => {
    const checkpoint = targetFinalityRecord.targetFinalityCheckpoint;
    const payload = {
        objectType: 'TargetAcceptedRecord',
        objectVersion: 1,
        ceremonyId,
        electionManifestDigest: checkpoint.electionManifestDigest,
        targetFinalityScope: 'target',
        targetProposalDigest: targetFinalityRecord.targetProposalDigest,
        topKEvaluationRecordDigest: checkpoint.topKEvaluationRecordDigest,
        targetContextDigest: deriveProtocolDigest('TargetContextDigest', {
            target: 'accepted-target-context',
        }),
        targetFinalityRecordDigest:
            targetFinalityRecord.targetFinalityRecordDigest,
        targetFinalityCheckpointDigest:
            checkpoint.targetFinalityCheckpointDigest,
        evaluationProofRecordDigest:
            evaluationProofRecord.evaluationProofRecordDigest,
        evaluationProofProfileDigest:
            evaluationProofRecord.evaluationProofProfileDigest,
        targetPreimageDigest: deriveProtocolDigest('TargetPreimageDigest', {
            target: 'accepted-target-preimage',
        }),
        targetCiphertextDigest: evaluationProofRecord.targetCiphertextDigest,
        targetLayoutDigest: evaluationProofRecord.targetLayoutDigest,
        acceptanceMode: 'evaluation-proof',
        kllpsTargetDecryptionProfileDigest:
            manifestOpaqueBindings.kllpsTargetDecryptionProfileDigest,
        targetBasisDigest: manifestOpaqueBindings.targetBasisDigest,
        cpadProfileId: manifestOpaqueBindings.cpadProfileId,
        cpadProfileDigest: manifestOpaqueBindings.cpadProfileDigest,
        thresholdDecryptionProfileId:
            manifestOpaqueBindings.thresholdDecryptionProfileId,
        thresholdDecryptionProfileDigest:
            manifestOpaqueBindings.thresholdDecryptionProfileDigest,
        boardSequence: 3,
        boardPosition: 0,
        organizerIdentity: 'organizer',
    } as const;
    const targetAcceptedRecordDigest =
        deriveTargetAcceptedRecordDigest(payload);

    return {
        ...payload,
        targetAcceptedRecordDigest,
        signature: createSignature(
            'TargetAcceptedRecord',
            'Organizer',
            'organizer',
            organizerPublicKeyDigest,
            targetAcceptedRecordDigest,
            {
                contextDigest: payload.targetContextDigest,
                manifestDigest: payload.electionManifestDigest,
            },
        ),
    };
};

const signTargetAcceptedRecord = (
    targetAcceptedRecord: TargetAcceptedRecord,
    boardHeadDigest: string,
): TargetAcceptedRecord => ({
    ...targetAcceptedRecord,
    signature: createSignature(
        'TargetAcceptedRecord',
        'Organizer',
        targetAcceptedRecord.organizerIdentity,
        organizerPublicKeyDigest,
        targetAcceptedRecord.targetAcceptedRecordDigest,
        {
            boardHeadDigest,
            contextDigest: targetAcceptedRecord.targetContextDigest,
            manifestDigest: targetAcceptedRecord.electionManifestDigest,
        },
    ),
});

const createDecryptionShare = (
    targetAcceptedRecord: TargetAcceptedRecord,
): TopKDecryptionShareShell => {
    const payload = {
        objectType: 'TopKDecryptionShare',
        objectVersion: 1,
        ceremonyId,
        electionManifestDigest: targetAcceptedRecord.electionManifestDigest,
        trusteeIdentity: 'participant-1',
        targetAcceptedRecordDigest:
            targetAcceptedRecord.targetAcceptedRecordDigest,
        targetProposalDigest: targetAcceptedRecord.targetProposalDigest,
        targetPreimageDigest: targetAcceptedRecord.targetPreimageDigest,
        targetFinalityRecordDigest:
            targetAcceptedRecord.targetFinalityRecordDigest,
        targetFinalityCheckpointDigest:
            targetAcceptedRecord.targetFinalityCheckpointDigest,
        evaluationProofRecordDigest:
            targetAcceptedRecord.evaluationProofRecordDigest,
        topKEvaluationRecordDigest:
            targetAcceptedRecord.topKEvaluationRecordDigest,
        targetContextDigest: targetAcceptedRecord.targetContextDigest,
        targetCiphertextDigest: targetAcceptedRecord.targetCiphertextDigest,
        cpadProfileDigest: targetAcceptedRecord.cpadProfileDigest,
        thresholdDecryptionProfileDigest:
            targetAcceptedRecord.thresholdDecryptionProfileDigest,
        kllpsTargetDecryptionProfileDigest:
            targetAcceptedRecord.kllpsTargetDecryptionProfileDigest,
        targetDecryptionPreparationRecordDigest: deriveProtocolDigest(
            'TargetDecryptionPreparationRecordDigest',
            { target: 'accepted-target-decryption-preparation' },
        ),
        targetDecryptionCiphertextDigest: deriveProtocolDigest(
            'TargetDecryptionCiphertextDigest',
            { target: 'accepted-target-decryption-ciphertext' },
        ),
        targetBasisDigest: targetAcceptedRecord.targetBasisDigest,
        thresholdShareVerificationKeyRoot: deriveProtocolDigest(
            'ThresholdShareVerificationKeyRoot',
            { trustee: 'participant-1' },
        ),
        thresholdShareVerificationKeyDigest: deriveProtocolDigest(
            'ThresholdShareVerificationKeyDigest',
            { trustee: 'participant-1' },
        ),
        trusteeThresholdVerificationKeyDigest: deriveProtocolDigest(
            'TrusteeThresholdVerificationKeyDigest',
            { trustee: 'participant-1', scope: 'trustee' },
        ),
        boardSequence: 4,
        boardPosition: 0,
        recoveryEpoch: 0,
        deviceEpoch: 0,
        shareRoot: deriveProtocolDigest('TopKDecryptionShareDigest', {
            share: 'participant-1',
        }),
    } as const;
    const topKDecryptionShareDigest = deriveTopKDecryptionShareDigest(payload);

    return {
        ...payload,
        topKDecryptionShareDigest,
        signature: createSignature(
            'TopKDecryptionShare',
            'Trustee',
            'participant-1',
            getParticipantSigningPublicKeyDigest('participant-1'),
            topKDecryptionShareDigest,
            {
                contextDigest: payload.targetContextDigest,
                manifestDigest: payload.electionManifestDigest,
            },
        ),
    };
};

const signDecryptionShare = (
    decryptionShare: TopKDecryptionShareShell,
    boardHeadDigest: string,
): TopKDecryptionShareShell => ({
    ...decryptionShare,
    signature: createSignature(
        'TopKDecryptionShare',
        'Trustee',
        decryptionShare.trusteeIdentity,
        getParticipantSigningPublicKeyDigest(decryptionShare.trusteeIdentity),
        decryptionShare.topKDecryptionShareDigest,
        {
            boardHeadDigest,
            contextDigest: decryptionShare.targetContextDigest,
            manifestDigest: decryptionShare.electionManifestDigest,
        },
    ),
});

const createLocalReplayRecord = (
    targetFinalityRecord: ReturnType<typeof createTargetFinalityRecord>,
    evaluationProofRecord: EvaluationProofRecord,
): LocalReplayRecord => {
    const payload = {
        objectType: 'LocalReplayRecord',
        objectVersion: 1,
        ceremonyId,
        electionManifestDigest:
            targetFinalityRecord.targetFinalityCheckpoint
                .electionManifestDigest,
        participantIdentity: 'participant-1',
        targetProposalDigest: targetFinalityRecord.targetProposalDigest,
        targetFinalityRecordDigest:
            targetFinalityRecord.targetFinalityRecordDigest,
        evaluationProofRecordDigest:
            evaluationProofRecord.evaluationProofRecordDigest,
        replayContextDigest: deriveProtocolDigest('ActionContextDigest', {
            replay: 'participant-1',
        }),
        recoveryEpoch: 0,
        deviceEpoch: 0,
        localReplayDiagnosticDigest: deriveProtocolDigest(
            'LocalReplayDiagnosticDigest',
            {
                replay: 'participant-1',
            },
        ),
    } as const;
    const localReplayRecordDigest = deriveLocalReplayRecordDigest(payload);

    return {
        ...payload,
        localReplayRecordDigest,
        signature: createSignature(
            'LocalReplayRecord',
            'Participant',
            'participant-1',
            getParticipantSigningPublicKeyDigest('participant-1'),
            localReplayRecordDigest,
            {
                contextDigest: payload.replayContextDigest,
                manifestDigest: payload.electionManifestDigest,
            },
        ),
    };
};

const signLocalReplayRecord = (
    localReplayRecord: LocalReplayRecord,
    boardHeadDigest: string,
): LocalReplayRecord => ({
    ...localReplayRecord,
    signature: createSignature(
        'LocalReplayRecord',
        'Participant',
        localReplayRecord.participantIdentity,
        getParticipantSigningPublicKeyDigest(
            localReplayRecord.participantIdentity,
        ),
        localReplayRecord.localReplayRecordDigest,
        {
            boardHeadDigest,
            contextDigest: localReplayRecord.replayContextDigest,
            manifestDigest: localReplayRecord.electionManifestDigest,
        },
    ),
});

type AcceptedTargetScenario = {
    readonly head0: ReturnType<typeof createBoardHead>;
    readonly head1: ReturnType<typeof createBoardHead>;
    readonly evaluationProofHead: ReturnType<typeof createBoardHead>;
    readonly acceptedHead: ReturnType<typeof createBoardHead>;
    readonly boardEvidence: ReturnType<typeof createBoardEvidence>;
    readonly targetFinalityRecord: ReturnType<
        typeof createTargetFinalityRecord
    >;
    readonly targetFinalityVerification: ReturnType<
        typeof verifyTargetFinality
    >;
    readonly evaluationProofRecord: EvaluationProofRecord;
    readonly targetAcceptedRecord: TargetAcceptedRecord;
    readonly targetAcceptedRecordInclusionProof: ReturnType<
        typeof createBoardHeadWithObjects
    >['inclusionProofs'][number];
    readonly targetAcceptedRecordVerification: ReturnType<
        typeof verifyTargetAcceptedRecordShell
    >;
};

const createAcceptedTargetScenario = (): AcceptedTargetScenario => {
    const head0 = createBoardHead(0, null);
    const head1 = createTargetProposalHead(1, head0.headDigest);
    const targetFinalityRecord = createTargetFinalityRecord(head1);
    const targetFinalityVerification = verifyTargetFinality({
        boardEvidence: createBoardEvidence([head0, head1]),
        record: targetFinalityRecord,
        witnessPolicy,
        targetFinalityPolicy,
        witnessPublicKeyDigests,
    });
    const evaluationProofRecord =
        createEvaluationProofRecord(targetFinalityRecord);
    const { head: evaluationProofHead } = createBoardHeadWithObjects(
        2,
        head1.headDigest,
        [
            {
                objectType: 'EvaluationProofRecord',
                objectDigest: evaluationProofRecord.evaluationProofRecordDigest,
                boardPosition: evaluationProofRecord.boardPosition,
            },
        ],
    );
    const unsignedTargetAcceptedRecord = createTargetAcceptedRecord(
        targetFinalityRecord,
        evaluationProofRecord,
    );
    const { head: acceptedHead, inclusionProofs } = createBoardHeadWithObjects(
        3,
        evaluationProofHead.headDigest,
        [
            {
                objectType: 'TargetAcceptedRecord',
                objectDigest:
                    unsignedTargetAcceptedRecord.targetAcceptedRecordDigest,
                boardPosition: unsignedTargetAcceptedRecord.boardPosition,
            },
        ],
    );
    const targetAcceptedRecord = signTargetAcceptedRecord(
        unsignedTargetAcceptedRecord,
        acceptedHead.headDigest,
    );
    const boardEvidence = createBoardEvidence([
        head0,
        head1,
        evaluationProofHead,
        acceptedHead,
    ]);
    const targetAcceptedRecordInclusionProof = inclusionProofs[0];
    const targetAcceptedRecordVerification = verifyTargetAcceptedRecordShell({
        boardEvidence,
        targetAcceptedRecord,
        targetAcceptedRecordInclusionProof,
        targetFinalityRecord,
        targetFinalityVerification,
        evaluationProofRecord,
        expectedOrganizerPublicKeyDigest: organizerPublicKeyDigest,
    });

    return {
        head0,
        head1,
        evaluationProofHead,
        acceptedHead,
        boardEvidence,
        targetFinalityRecord,
        targetFinalityVerification,
        evaluationProofRecord,
        targetAcceptedRecord,
        targetAcceptedRecordInclusionProof,
        targetAcceptedRecordVerification,
    };
};

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
