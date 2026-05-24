import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BoardConsistencyInput,
    InclusionProof,
    SignedBoardHead,
    TargetFinalityRecord,
    WitnessCheckpoint,
} from '@sealed-lattice/types';

import {
    deriveBoardEntryMerklePath,
    deriveBoardEntryDigest,
    deriveBoardHeadDigest,
    deriveBoardRootDigest,
    deriveInclusionProofDigest,
} from '../../src/board/index';
import {
    deriveTargetFinalityCheckpointDigest,
    deriveTargetFinalityRecordDigest,
    deriveTargetProposalDigest,
    deriveWitnessCheckpointDigest,
} from '../../src/finality/index';

import {
    boardPolicyDigest,
    boardPublicKeyDigest,
    ceremonyId,
    createKeyFixture,
    createSignature,
    defaultThresholdProfileDigest,
    defaultTopKEvaluationRecordDigest,
    manifestOpaqueBindings,
    targetFinalityPolicyDigest,
    witnessIdentities,
    witnessPolicyDigest,
    witnessPublicKeyDigests,
} from './election-foundation-fixture-constants';

export const createBoardHead = (
    boardSequence: number,
    previousHeadDigest: string | null,
    branchName = 'main',
    boardEntryDigests?: readonly string[],
): SignedBoardHead => {
    const resolvedBoardEntryDigests = boardEntryDigests ?? [
        deriveProtocolDigest('BoardEntryDigest', {
            branchName,
            marker: 'empty-board-head',
            boardSequence,
        }),
    ];
    const unsignedHead: SignedBoardHead = {
        objectType: 'BoardHead',
        objectVersion: 1,
        headDigest: '',
        ceremonyId,
        boardSequence,
        boardRoot: deriveBoardRootDigest(resolvedBoardEntryDigests),
        previousHeadDigest,
        boardPolicyDigest,
        signature: createSignature(
            'BoardHead',
            'Board',
            'board',
            boardPublicKeyDigest,
            'placeholder',
        ),
    };
    const headDigest = deriveBoardHeadDigest(unsignedHead);

    return {
        ...unsignedHead,
        headDigest,
        signature: createSignature(
            'BoardHead',
            'Board',
            'board',
            boardPublicKeyDigest,
            headDigest,
        ),
    };
};

export const createInclusionProof = (
    head: SignedBoardHead,
    includedObjectType: InclusionProof['includedObjectType'],
    includedObjectDigest: string,
    boardPosition = 0,
    boardEntryDigests?: readonly string[],
): InclusionProof => {
    const boardEntryDigest = deriveBoardEntryDigest({
        boardPosition,
        includedObjectDigest,
        includedObjectType,
    });
    const resolvedBoardEntryDigests =
        boardEntryDigests ??
        Array.from({ length: boardPosition + 1 }, (_, index) =>
            index === boardPosition
                ? boardEntryDigest
                : deriveProtocolDigest('BoardEntryDigest', {
                      filler: index,
                      headDigest: head.headDigest,
                  }),
        );
    const payload = {
        boardHeadDigest: head.headDigest,
        boardSequence: head.boardSequence,
        boardPosition,
        includedObjectType,
        includedObjectDigest,
        boardEntryDigest,
        boardRoot: deriveBoardRootDigest(resolvedBoardEntryDigests),
        boardEntryCount: resolvedBoardEntryDigests.length,
        boardEntryMerklePath: deriveBoardEntryMerklePath(
            resolvedBoardEntryDigests,
            boardPosition,
        ),
    };

    return {
        ...payload,
        inclusionProofDigest: deriveInclusionProofDigest(payload),
    };
};

export const createBoardHeadWithObjects = (
    boardSequence: number,
    previousHeadDigest: string | null,
    objects: readonly {
        readonly objectType: InclusionProof['includedObjectType'];
        readonly objectDigest: string;
        readonly boardPosition: number;
    }[],
    branchName = 'main',
): {
    readonly head: SignedBoardHead;
    readonly inclusionProofs: readonly InclusionProof[];
} => {
    const maximumBoardPosition = Math.max(
        0,
        ...objects.map((object) => object.boardPosition),
    );
    const boardEntryDigests = Array.from(
        { length: maximumBoardPosition + 1 },
        (_, boardPosition) => {
            const object = objects.find(
                (entry) => entry.boardPosition === boardPosition,
            );

            return object === undefined
                ? deriveProtocolDigest('BoardEntryDigest', {
                      filler: boardPosition,
                      branchName,
                      boardSequence,
                  })
                : deriveBoardEntryDigest({
                      boardPosition: object.boardPosition,
                      includedObjectDigest: object.objectDigest,
                      includedObjectType: object.objectType,
                  });
        },
    );
    const head = createBoardHead(
        boardSequence,
        previousHeadDigest,
        branchName,
        boardEntryDigests,
    );
    const inclusionProofs = objects.map((object) =>
        createInclusionProof(
            head,
            object.objectType,
            object.objectDigest,
            object.boardPosition,
            boardEntryDigests,
        ),
    );

    return { head, inclusionProofs };
};

export const createTargetProposalHead = (
    boardSequence: number,
    previousHeadDigest: string | null,
    branchName = 'main',
    topKEvaluationRecordDigest = defaultTopKEvaluationRecordDigest,
): SignedBoardHead =>
    createBoardHeadWithObjects(
        boardSequence,
        previousHeadDigest,
        [
            {
                objectType: 'TopKEvaluationRecord',
                objectDigest: topKEvaluationRecordDigest,
                boardPosition: 0,
            },
        ],
        branchName,
    ).head;

export const createWitnessCheckpoint = (
    witnessIdentity: string,
    finalizedBoardHeadDigest: string,
    targetProposalDigest = deriveProtocolDigest('TargetProposalDigest', {
        finalizedBoardHeadDigest,
        witnessIdentity,
    }),
    targetFinalityCheckpointDigest = deriveProtocolDigest(
        'TargetFinalityCheckpointDigest',
        {
            finalizedBoardHeadDigest,
            targetProposalDigest,
            witnessIdentity,
        },
    ),
    electionManifestDigest: string | null = null,
    overrides: Partial<WitnessCheckpoint> = {},
): WitnessCheckpoint => {
    const checkpointPayload = {
        objectType: 'WitnessCheckpoint',
        objectVersion: 1,
        ceremonyId,
        targetFinalityScope: 'target',
        targetProposalDigest,
        targetFinalityCheckpointDigest,
        witnessPolicyDigest,
        targetFinalityPolicyDigest,
        witnessIdentity,
        ...overrides,
    } satisfies Omit<WitnessCheckpoint, 'checkpointDigest' | 'signature'>;
    const checkpointDigest = deriveWitnessCheckpointDigest(checkpointPayload);

    return {
        ...checkpointPayload,
        checkpointDigest,
        signature: createSignature(
            'WitnessCheckpoint',
            'Witness',
            witnessIdentity,
            witnessPublicKeyDigests[witnessIdentity] ??
                createKeyFixture(`unknown-witness:${witnessIdentity}`)
                    .publicKeyDigest,
            checkpointDigest,
            {
                boardHeadDigest: finalizedBoardHeadDigest,
                manifestDigest: electionManifestDigest,
            },
        ),
    };
};

export const createTargetFinalityRecord = (
    finalizedHead: SignedBoardHead,
    topKEvaluationRecordDigest = defaultTopKEvaluationRecordDigest,
    witnessCount = 5,
): TargetFinalityRecord => {
    const proposalPayload = {
        ceremonyId,
        electionManifestDigest: deriveProtocolDigest('ElectionManifestDigest', {
            ceremonyId,
            marker: 'default-manifest',
        }),
        thresholdProfileDigest: defaultThresholdProfileDigest,
        evaluationContextDigest: deriveProtocolDigest(
            'EvaluationContextDigest',
            { ceremonyId, marker: 'top-k-evaluation' },
        ),
        topKEvaluationRecordDigest,
        topKCiphertextDigest: deriveProtocolDigest('CiphertextRoot', {
            ceremonyId,
            marker: 'c-top-k',
        }),
        publicSlotMaskDigest: deriveProtocolDigest('PublicSlotMaskDigest', {
            ceremonyId,
            marker: 'top-k-mask',
        }),
        targetCiphertextDigest: deriveProtocolDigest('CiphertextRoot', {
            ceremonyId,
            marker: 'c-target',
        }),
        targetLayoutDigest: deriveProtocolDigest('TargetLayoutDigest', {
            layout: 'WinnerRankTopK-v1',
        }),
        evaluationProofProfileDigest:
            manifestOpaqueBindings.evaluationProofProfileDigest,
        targetFinalityPolicyDigest,
    };
    const targetProposalDigest = deriveTargetProposalDigest(proposalPayload);
    const targetFinalityCheckpointPayload = {
        ...proposalPayload,
        targetProposalDigest,
        objectType: 'TargetFinalityCheckpoint',
        objectVersion: 1,
        boardPolicyDigest,
        finalizedBoardHeadDigest: finalizedHead.headDigest,
        witnessPolicyDigest,
    } as const;
    const targetFinalityCheckpointDigest = deriveTargetFinalityCheckpointDigest(
        targetFinalityCheckpointPayload,
    );
    const targetFinalityCheckpoint = {
        ...targetFinalityCheckpointPayload,
        targetFinalityCheckpointDigest,
    };
    const inclusionProof = createInclusionProof(
        finalizedHead,
        'TopKEvaluationRecord',
        topKEvaluationRecordDigest,
    );
    const witnessCheckpoints = witnessIdentities
        .slice(0, witnessCount)
        .map((witnessIdentity) =>
            createWitnessCheckpoint(
                witnessIdentity,
                finalizedHead.headDigest,
                targetProposalDigest,
                targetFinalityCheckpointDigest,
                proposalPayload.electionManifestDigest,
            ),
        );
    const payload = {
        objectType: 'TargetFinalityRecord',
        objectVersion: 1,
        ceremonyId,
        targetFinalityScope: 'target',
        targetProposalDigest,
        targetFinalityCheckpoint,
        witnessPolicyDigest,
        targetFinalityPolicyDigest,
        inclusionProof,
        witnessCheckpoints,
    } satisfies Omit<TargetFinalityRecord, 'targetFinalityRecordDigest'>;

    return {
        ...payload,
        targetFinalityRecordDigest: deriveTargetFinalityRecordDigest(payload),
    };
};

export const createBoardEvidence = (
    heads: readonly SignedBoardHead[],
): BoardConsistencyInput => ({
    ceremonyId,
    boardPolicyDigest,
    signedBoardHeads: heads,
    expectedBoardPublicKeyDigest: boardPublicKeyDigest,
});
