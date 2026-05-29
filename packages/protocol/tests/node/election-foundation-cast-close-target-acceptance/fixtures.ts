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
    deriveCloseRecordHash,
    deriveLocalReplayRecordHash,
    derivePostVotingClosedContextHash,
    deriveProtocolHash,
    deriveTargetAcceptedRecordHash,
    deriveTopKDecryptionShareHash,
    getParticipantSigningPublicKeyHash,
    manifestOpaqueBindings,
    organizerPublicKeyHash,
    verifyTargetAcceptedRecordShell,
    verifyTargetFinality,
    witnessPolicy,
    targetFinalityPolicy,
    witnessPublicKeyHashes,
} from '../election-foundation-test-helpers';

export const closeRecordElectionManifestHash = deriveProtocolHash(
    'ElectionManifestHash',
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
    const closedHead = createBoardHead(1, genesisHead.headHash);
    const closedBoardHeadHash = input?.useGenesisAsClosedHead
        ? genesisHead.headHash
        : closedHead.headHash;
    const closeRecordPayload = {
        objectType: 'CloseRecord',
        objectVersion: 1,
        ceremonyId,
        electionManifestHash: closeRecordElectionManifestHash,
        closeKind: 'VotingClosed',
        closedBoardHeadHash,
        boardSequence: 2,
        boardPosition: 0,
        organizerIdentity: 'organizer',
    } satisfies Omit<
        CloseRecord,
        'closeRecordHash' | 'postVotingClosedContextHash' | 'signature'
    >;
    const closeRecordHash = deriveCloseRecordHash(closeRecordPayload);
    const { head: closeHead, inclusionProofs } = createBoardHeadWithObjects(
        2,
        closedHead.headHash,
        [
            {
                objectType: 'CloseRecord',
                objectHash: closeRecordHash,
                boardPosition: closeRecordPayload.boardPosition,
            },
        ],
    );
    const postVotingClosedContextHash = derivePostVotingClosedContextHash({
        ceremonyId,
        closeRecordHash,
        electionManifestHash: closeRecordElectionManifestHash,
        votingClosedBoardHeadHash: closeHead.headHash,
    });
    const closeRecord: CloseRecord = {
        ...closeRecordPayload,
        closeRecordHash,
        postVotingClosedContextHash,
        signature: createSignature(
            'CloseRecord',
            'Organizer',
            'organizer',
            organizerPublicKeyHash,
            closeRecordHash,
            {
                boardHeadHash: closeHead.headHash,
                contextHash: postVotingClosedContextHash,
                manifestHash: closeRecordElectionManifestHash,
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

export const deriveEvaluationProofRecordHash = (
    proofRecord: Omit<EvaluationProofRecord, 'evaluationProofRecordHash'>,
): string =>
    deriveProtocolHash('ChallengeDomainHash', {
        targetCiphertextHash: proofRecord.targetCiphertextHash,
        topKCiphertextHash: proofRecord.topKCiphertextHash,
        ceremonyId: proofRecord.ceremonyId,
        electionManifestHash: proofRecord.electionManifestHash,
        evaluationContextHash: proofRecord.evaluationContextHash,
        evaluationProofProfileHash: proofRecord.evaluationProofProfileHash,
        objectType: proofRecord.objectType,
        objectVersion: proofRecord.objectVersion,
        proofRoot: proofRecord.proofRoot,
        publicSlotMaskHash: proofRecord.publicSlotMaskHash,
        purpose: 'fixture-evaluation-proof-record-v1',
        targetFinalityRecordHash: proofRecord.targetFinalityRecordHash,
        targetLayoutHash: proofRecord.targetLayoutHash,
        targetProposalHash: proofRecord.targetProposalHash,
        topKEvaluationRecordHash: proofRecord.topKEvaluationRecordHash,
    });

export const createEvaluationProofRecord = (
    targetFinalityRecord: ReturnType<typeof createTargetFinalityRecord>,
): EvaluationProofRecord => {
    const checkpoint = targetFinalityRecord.targetFinalityCheckpoint;
    const payload = {
        objectType: 'EvaluationProofRecord',
        objectVersion: 1,
        ceremonyId,
        electionManifestHash: checkpoint.electionManifestHash,
        targetProposalHash: targetFinalityRecord.targetProposalHash,
        topKEvaluationRecordHash: checkpoint.topKEvaluationRecordHash,
        targetFinalityRecordHash: targetFinalityRecord.targetFinalityRecordHash,
        evaluationProofProfileHash: checkpoint.evaluationProofProfileHash,
        evaluationContextHash: checkpoint.evaluationContextHash,
        topKCiphertextHash: checkpoint.topKCiphertextHash,
        publicSlotMaskHash: checkpoint.publicSlotMaskHash,
        targetCiphertextHash: checkpoint.targetCiphertextHash,
        targetLayoutHash: checkpoint.targetLayoutHash,
        proofRoot: deriveProtocolHash('ChallengeDomainHash', {
            payload: { proof: 'mandatory-pq-evaluation-proof' },
            purpose: 'fixture-evaluation-proof-root-v1',
        }),
        boardSequence: 2,
        boardPosition: 0,
    } as const;

    return {
        ...payload,
        evaluationProofRecordHash: deriveEvaluationProofRecordHash(payload),
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
        electionManifestHash: checkpoint.electionManifestHash,
        targetFinalityScope: 'target',
        targetProposalHash: targetFinalityRecord.targetProposalHash,
        topKEvaluationRecordHash: checkpoint.topKEvaluationRecordHash,
        targetContextHash: deriveProtocolHash('ChallengeDomainHash', {
            payload: { target: 'accepted-target-context' },
            purpose: 'fixture-target-context-v1',
        }),
        targetFinalityRecordHash: targetFinalityRecord.targetFinalityRecordHash,
        targetFinalityCheckpointHash: checkpoint.targetFinalityCheckpointHash,
        evaluationProofRecordHash:
            evaluationProofRecord.evaluationProofRecordHash,
        evaluationProofProfileHash:
            evaluationProofRecord.evaluationProofProfileHash,
        targetPreimageHash: deriveProtocolHash('ChallengeDomainHash', {
            payload: { target: 'accepted-target-preimage' },
            purpose: 'fixture-target-preimage-v1',
        }),
        targetCiphertextHash: evaluationProofRecord.targetCiphertextHash,
        targetLayoutHash: evaluationProofRecord.targetLayoutHash,
        acceptanceMode: 'evaluation-proof',
        kllpsTargetDecryptionProfileHash:
            manifestOpaqueBindings.kllpsTargetDecryptionProfileHash,
        targetBasisHash: manifestOpaqueBindings.targetBasisHash,
        cpadProfileId: manifestOpaqueBindings.cpadProfileId,
        cpadProfileHash: manifestOpaqueBindings.cpadProfileHash,
        thresholdDecryptionProfileId:
            manifestOpaqueBindings.thresholdDecryptionProfileId,
        thresholdDecryptionProfileHash:
            manifestOpaqueBindings.thresholdDecryptionProfileHash,
        boardSequence: 3,
        boardPosition: 0,
        organizerIdentity: 'organizer',
    } as const;
    const targetAcceptedRecordHash = deriveTargetAcceptedRecordHash(payload);

    return {
        ...payload,
        targetAcceptedRecordHash,
        signature: createSignature(
            'TargetAcceptedRecord',
            'Organizer',
            'organizer',
            organizerPublicKeyHash,
            targetAcceptedRecordHash,
            {
                contextHash: payload.targetContextHash,
                manifestHash: payload.electionManifestHash,
            },
        ),
    };
};

export const signTargetAcceptedRecord = (
    targetAcceptedRecord: TargetAcceptedRecord,
    boardHeadHash: string,
): TargetAcceptedRecord => ({
    ...targetAcceptedRecord,
    signature: createSignature(
        'TargetAcceptedRecord',
        'Organizer',
        targetAcceptedRecord.organizerIdentity,
        organizerPublicKeyHash,
        targetAcceptedRecord.targetAcceptedRecordHash,
        {
            boardHeadHash,
            contextHash: targetAcceptedRecord.targetContextHash,
            manifestHash: targetAcceptedRecord.electionManifestHash,
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
        electionManifestHash: targetAcceptedRecord.electionManifestHash,
        trusteeIdentity: 'participant-1',
        targetAcceptedRecordHash: targetAcceptedRecord.targetAcceptedRecordHash,
        targetProposalHash: targetAcceptedRecord.targetProposalHash,
        targetPreimageHash: targetAcceptedRecord.targetPreimageHash,
        targetFinalityRecordHash: targetAcceptedRecord.targetFinalityRecordHash,
        targetFinalityCheckpointHash:
            targetAcceptedRecord.targetFinalityCheckpointHash,
        evaluationProofRecordHash:
            targetAcceptedRecord.evaluationProofRecordHash,
        topKEvaluationRecordHash: targetAcceptedRecord.topKEvaluationRecordHash,
        targetContextHash: targetAcceptedRecord.targetContextHash,
        targetCiphertextHash: targetAcceptedRecord.targetCiphertextHash,
        cpadProfileHash: targetAcceptedRecord.cpadProfileHash,
        thresholdDecryptionProfileHash:
            targetAcceptedRecord.thresholdDecryptionProfileHash,
        kllpsTargetDecryptionProfileHash:
            targetAcceptedRecord.kllpsTargetDecryptionProfileHash,
        targetDecryptionPreparationRecordHash: deriveProtocolHash(
            'ChallengeDomainHash',
            {
                payload: { target: 'accepted-target-decryption-preparation' },
                purpose: 'fixture-target-decryption-preparation-record-v1',
            },
        ),
        targetDecryptionCiphertextHash: deriveProtocolHash(
            'ChallengeDomainHash',
            {
                payload: { target: 'accepted-target-decryption-ciphertext' },
                purpose: 'fixture-target-decryption-ciphertext-v1',
            },
        ),
        targetBasisHash: targetAcceptedRecord.targetBasisHash,
        thresholdShareVerificationKeyRoot: deriveProtocolHash(
            'ThresholdShareVerificationKeyRoot',
            { trustee: 'participant-1' },
        ),
        thresholdShareVerificationKeyHash: deriveProtocolHash(
            'ThresholdShareVerificationKeyHash',
            { trustee: 'participant-1' },
        ),
        trusteeThresholdVerificationKeyHash: deriveProtocolHash(
            'TrusteeThresholdVerificationKeyHash',
            { trustee: 'participant-1', scope: 'trustee' },
        ),
        boardSequence: 4,
        boardPosition: 0,
        recoveryEpoch: 0,
        deviceEpoch: 0,
        shareRoot: deriveProtocolHash('TopKDecryptionShareHash', {
            share: 'participant-1',
        }),
    } as const;
    const topKDecryptionShareHash = deriveTopKDecryptionShareHash(payload);

    return {
        ...payload,
        topKDecryptionShareHash,
        signature: createSignature(
            'TopKDecryptionShare',
            'Trustee',
            'participant-1',
            getParticipantSigningPublicKeyHash('participant-1'),
            topKDecryptionShareHash,
            {
                contextHash: payload.targetContextHash,
                manifestHash: payload.electionManifestHash,
            },
        ),
    };
};

export const signDecryptionShare = (
    decryptionShare: TopKDecryptionShareShell,
    boardHeadHash: string,
): TopKDecryptionShareShell => ({
    ...decryptionShare,
    signature: createSignature(
        'TopKDecryptionShare',
        'Trustee',
        decryptionShare.trusteeIdentity,
        getParticipantSigningPublicKeyHash(decryptionShare.trusteeIdentity),
        decryptionShare.topKDecryptionShareHash,
        {
            boardHeadHash,
            contextHash: decryptionShare.targetContextHash,
            manifestHash: decryptionShare.electionManifestHash,
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
        electionManifestHash:
            targetFinalityRecord.targetFinalityCheckpoint.electionManifestHash,
        participantIdentity: 'participant-1',
        targetProposalHash: targetFinalityRecord.targetProposalHash,
        targetFinalityRecordHash: targetFinalityRecord.targetFinalityRecordHash,
        evaluationProofRecordHash:
            evaluationProofRecord.evaluationProofRecordHash,
        replayContextHash: deriveProtocolHash('ActionContextHash', {
            replay: 'participant-1',
        }),
        recoveryEpoch: 0,
        deviceEpoch: 0,
        localReplayDiagnosticHash: deriveProtocolHash('ChallengeDomainHash', {
            payload: { replay: 'participant-1' },
            purpose: 'fixture-local-replay-diagnostic-v1',
        }),
    } as const;
    const localReplayRecordHash = deriveLocalReplayRecordHash(payload);

    return {
        ...payload,
        localReplayRecordHash,
        signature: createSignature(
            'LocalReplayRecord',
            'Participant',
            'participant-1',
            getParticipantSigningPublicKeyHash('participant-1'),
            localReplayRecordHash,
            {
                contextHash: payload.replayContextHash,
                manifestHash: payload.electionManifestHash,
            },
        ),
    };
};

export const signLocalReplayRecord = (
    localReplayRecord: LocalReplayRecord,
    boardHeadHash: string,
): LocalReplayRecord => ({
    ...localReplayRecord,
    signature: createSignature(
        'LocalReplayRecord',
        'Participant',
        localReplayRecord.participantIdentity,
        getParticipantSigningPublicKeyHash(
            localReplayRecord.participantIdentity,
        ),
        localReplayRecord.localReplayRecordHash,
        {
            boardHeadHash,
            contextHash: localReplayRecord.replayContextHash,
            manifestHash: localReplayRecord.electionManifestHash,
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
    const head1 = createTargetProposalHead(1, head0.headHash);
    const targetFinalityRecord = createTargetFinalityRecord(head1);
    const targetFinalityVerification = verifyTargetFinality({
        boardEvidence: createBoardEvidence([head0, head1]),
        record: targetFinalityRecord,
        witnessPolicy,
        targetFinalityPolicy,
        witnessPublicKeyHashes,
    });
    const evaluationProofRecord =
        createEvaluationProofRecord(targetFinalityRecord);
    const { head: evaluationProofHead } = createBoardHeadWithObjects(
        2,
        head1.headHash,
        [
            {
                objectType: 'EvaluationProofRecord',
                objectHash: evaluationProofRecord.evaluationProofRecordHash,
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
        evaluationProofHead.headHash,
        [
            {
                objectType: 'TargetAcceptedRecord',
                objectHash:
                    unsignedTargetAcceptedRecord.targetAcceptedRecordHash,
                boardPosition: unsignedTargetAcceptedRecord.boardPosition,
            },
        ],
    );
    const targetAcceptedRecord = signTargetAcceptedRecord(
        unsignedTargetAcceptedRecord,
        acceptedHead.headHash,
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
        expectedOrganizerPublicKeyHash: organizerPublicKeyHash,
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
