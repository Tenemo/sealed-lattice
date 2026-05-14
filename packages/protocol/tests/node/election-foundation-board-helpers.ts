import {
    deriveBoardEntryDigest,
    deriveBoardHeadDigest,
    deriveBoardRootDigest,
    deriveInclusionProofDigest,
    deriveProtocolDigest,
    deriveTargetFinalityRecordDigest,
    deriveWitnessCheckpointDigest,
} from '../../src/index';
import type {
    BoardConsistencyInput,
    InclusionProof,
    SignedBoardHead,
    TargetFinalityRecord,
    WitnessCheckpoint,
} from '../../src/index';

import {
    boardPolicyDigest,
    boardPublicKeyDigest,
    ceremonyId,
    createKeyFixture,
    createSignature,
    defaultTopKEvaluationRecordDigest,
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
        boardEntryDigests: resolvedBoardEntryDigests,
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
    overrides: Partial<WitnessCheckpoint> = {},
): WitnessCheckpoint => {
    const checkpointPayload = {
        objectType: 'WitnessCheckpoint',
        objectVersion: 1,
        ceremonyId,
        targetPhase: 'target',
        finalizedBoardHeadDigest,
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
            },
        ),
    };
};

export const createTargetFinalityRecord = (
    finalizedHead: SignedBoardHead,
    topKEvaluationRecordDigest = defaultTopKEvaluationRecordDigest,
    witnessCount = 5,
): TargetFinalityRecord => {
    const inclusionProof = createInclusionProof(
        finalizedHead,
        'TopKEvaluationRecord',
        topKEvaluationRecordDigest,
    );
    const witnessCheckpoints = witnessIdentities
        .slice(0, witnessCount)
        .map((witnessIdentity) =>
            createWitnessCheckpoint(witnessIdentity, finalizedHead.headDigest),
        );
    const payload = {
        objectType: 'TargetFinalityRecord',
        objectVersion: 1,
        ceremonyId,
        targetPhase: 'target',
        finalizedBoardHeadDigest: finalizedHead.headDigest,
        topKEvaluationRecordDigest,
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
