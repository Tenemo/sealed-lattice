import type {
    CloseRecord,
    EvaluationProofRecord,
    LocalReplayRecord,
    TargetAcceptedRecord,
    TopKDecryptionShareShell,
} from '@sealed-lattice/types';

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
    verifyTargetAcceptedRecordShell,
    verifyTargetFinality,
    witnessPolicy,
    targetFinalityPolicy,
    witnessPublicKeyDigests,
} from '../election-foundation-test-helpers';

export const closeRecordElectionManifestDigest = deriveProtocolDigest(
    'ElectionManifestDigest',
    { manifest: 'close-record-shell' },
);

export const createVotingCloseScenario = (input?: {
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

export const deriveEvaluationProofRecordDigest = (
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

export const createEvaluationProofRecord = (
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

export const createTargetAcceptedRecord = (
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

export const signTargetAcceptedRecord = (
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

export const createDecryptionShare = (
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

export const signDecryptionShare = (
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

export const createLocalReplayRecord = (
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

export const signLocalReplayRecord = (
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

export const createAcceptedTargetScenario = (): AcceptedTargetScenario => {
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
