import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    BoardConsistencyInput,
    InclusionProof,
    SignedBoardHead,
    TargetFinalityRecord,
    WitnessCheckpoint,
} from '@sealed-lattice/types';

import {
    deriveBoardEntryMerklePath,
    deriveBoardEntryHash,
    deriveBoardHeadHash,
    deriveBoardRootHash,
    deriveInclusionProofHash,
} from '../../src/board/index';
import {
    deriveTargetFinalityCheckpointHash,
    deriveTargetFinalityRecordHash,
    deriveTargetProposalHash,
    deriveWitnessCheckpointHash,
} from '../../src/finality/index';

import {
    boardPolicyHash,
    boardPublicKeyHash,
    ceremonyId,
    createKeyFixture,
    createSignature,
    defaultThresholdProfileHash,
    defaultTopKEvaluationRecordHash,
    manifestOpaqueBindings,
    targetFinalityPolicyHash,
    witnessIdentities,
    witnessPolicyHash,
    witnessPublicKeyHashes,
} from './election-foundation-fixture-constants';

export const createBoardHead = (
    boardSequence: number,
    previousHeadHash: string | null,
    branchName = 'main',
    boardEntryHashes?: readonly string[],
): SignedBoardHead => {
    const resolvedBoardEntryHashes = boardEntryHashes ?? [
        deriveProtocolHash('BoardEntryHash', {
            branchName,
            marker: 'empty-board-head',
            boardSequence,
        }),
    ];
    const unsignedHead: SignedBoardHead = {
        objectType: 'BoardHead',
        objectVersion: 1,
        headHash: '',
        ceremonyId,
        boardSequence,
        boardRoot: deriveBoardRootHash(resolvedBoardEntryHashes),
        previousHeadHash,
        boardPolicyHash,
        signature: createSignature(
            'BoardHead',
            'Board',
            'board',
            boardPublicKeyHash,
            'placeholder',
        ),
    };
    const headHash = deriveBoardHeadHash(unsignedHead);

    return {
        ...unsignedHead,
        headHash,
        signature: createSignature(
            'BoardHead',
            'Board',
            'board',
            boardPublicKeyHash,
            headHash,
        ),
    };
};

export const createInclusionProof = (
    head: SignedBoardHead,
    includedObjectType: InclusionProof['includedObjectType'],
    includedObjectHash: string,
    boardPosition = 0,
    boardEntryHashes?: readonly string[],
): InclusionProof => {
    const boardEntryHash = deriveBoardEntryHash({
        boardPosition,
        includedObjectHash,
        includedObjectType,
    });
    const resolvedBoardEntryHashes =
        boardEntryHashes ??
        Array.from({ length: boardPosition + 1 }, (_, index) =>
            index === boardPosition
                ? boardEntryHash
                : deriveProtocolHash('BoardEntryHash', {
                      filler: index,
                      headHash: head.headHash,
                  }),
        );
    const payload = {
        boardHeadHash: head.headHash,
        boardSequence: head.boardSequence,
        boardPosition,
        includedObjectType,
        includedObjectHash,
        boardEntryHash,
        boardRoot: deriveBoardRootHash(resolvedBoardEntryHashes),
        boardEntryCount: resolvedBoardEntryHashes.length,
        boardEntryMerklePath: deriveBoardEntryMerklePath(
            resolvedBoardEntryHashes,
            boardPosition,
        ),
    };

    return {
        ...payload,
        inclusionProofHash: deriveInclusionProofHash(payload),
    };
};

export const createBoardHeadWithObjects = (
    boardSequence: number,
    previousHeadHash: string | null,
    objects: readonly {
        readonly objectType: InclusionProof['includedObjectType'];
        readonly objectHash: string;
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
    const boardEntryHashes = Array.from(
        { length: maximumBoardPosition + 1 },
        (_, boardPosition) => {
            const object = objects.find(
                (entry) => entry.boardPosition === boardPosition,
            );

            return object === undefined
                ? deriveProtocolHash('BoardEntryHash', {
                      filler: boardPosition,
                      branchName,
                      boardSequence,
                  })
                : deriveBoardEntryHash({
                      boardPosition: object.boardPosition,
                      includedObjectHash: object.objectHash,
                      includedObjectType: object.objectType,
                  });
        },
    );
    const head = createBoardHead(
        boardSequence,
        previousHeadHash,
        branchName,
        boardEntryHashes,
    );
    const inclusionProofs = objects.map((object) =>
        createInclusionProof(
            head,
            object.objectType,
            object.objectHash,
            object.boardPosition,
            boardEntryHashes,
        ),
    );

    return { head, inclusionProofs };
};

export const createTargetProposalHead = (
    boardSequence: number,
    previousHeadHash: string | null,
    branchName = 'main',
    topKEvaluationRecordHash = defaultTopKEvaluationRecordHash,
): SignedBoardHead =>
    createBoardHeadWithObjects(
        boardSequence,
        previousHeadHash,
        [
            {
                objectType: 'TopKEvaluationRecord',
                objectHash: topKEvaluationRecordHash,
                boardPosition: 0,
            },
        ],
        branchName,
    ).head;

export const createWitnessCheckpoint = (
    witnessIdentity: string,
    finalizedBoardHeadHash: string,
    targetProposalHash = deriveProtocolHash('TargetProposalHash', {
        finalizedBoardHeadHash,
        witnessIdentity,
    }),
    targetFinalityCheckpointHash = deriveProtocolHash(
        'TargetFinalityCheckpointHash',
        {
            finalizedBoardHeadHash,
            targetProposalHash,
            witnessIdentity,
        },
    ),
    electionManifestHash: string | null = null,
    overrides: Partial<WitnessCheckpoint> = {},
): WitnessCheckpoint => {
    const checkpointPayload = {
        objectType: 'WitnessCheckpoint',
        objectVersion: 1,
        ceremonyId,
        targetFinalityScope: 'target',
        targetProposalHash,
        targetFinalityCheckpointHash,
        witnessPolicyHash,
        targetFinalityPolicyHash,
        witnessIdentity,
        ...overrides,
    } satisfies Omit<WitnessCheckpoint, 'checkpointHash' | 'signature'>;
    const checkpointHash = deriveWitnessCheckpointHash(checkpointPayload);

    return {
        ...checkpointPayload,
        checkpointHash,
        signature: createSignature(
            'WitnessCheckpoint',
            'Witness',
            witnessIdentity,
            witnessPublicKeyHashes[witnessIdentity] ??
                createKeyFixture(`unknown-witness:${witnessIdentity}`)
                    .publicKeyHash,
            checkpointHash,
            {
                boardHeadHash: finalizedBoardHeadHash,
                manifestHash: electionManifestHash,
            },
        ),
    };
};

export const createTargetFinalityRecord = (
    finalizedHead: SignedBoardHead,
    topKEvaluationRecordHash = defaultTopKEvaluationRecordHash,
    witnessCount = 5,
): TargetFinalityRecord => {
    const proposalPayload = {
        ceremonyId,
        electionManifestHash: deriveProtocolHash('ElectionManifestHash', {
            ceremonyId,
            marker: 'default-manifest',
        }),
        thresholdProfileHash: defaultThresholdProfileHash,
        evaluationContextHash: deriveProtocolHash('EvaluationContextHash', {
            ceremonyId,
            marker: 'top-k-evaluation',
        }),
        topKEvaluationRecordHash,
        topKCiphertextHash: deriveProtocolHash('CiphertextRoot', {
            ceremonyId,
            marker: 'c-top-k',
        }),
        publicSlotMaskHash: deriveProtocolHash('PublicSlotMaskHash', {
            ceremonyId,
            marker: 'top-k-mask',
        }),
        targetCiphertextHash: deriveProtocolHash('CiphertextRoot', {
            ceremonyId,
            marker: 'c-target',
        }),
        targetLayoutHash: deriveProtocolHash('TargetLayoutHash', {
            layout: 'WinnerRankTopK-v1',
        }),
        evaluationProofProfileHash:
            manifestOpaqueBindings.evaluationProofProfileHash,
        targetFinalityPolicyHash,
    };
    const targetProposalHash = deriveTargetProposalHash(proposalPayload);
    const targetFinalityCheckpointPayload = {
        ...proposalPayload,
        targetProposalHash,
        objectType: 'TargetFinalityCheckpoint',
        objectVersion: 1,
        boardPolicyHash,
        finalizedBoardHeadHash: finalizedHead.headHash,
        witnessPolicyHash,
    } as const;
    const targetFinalityCheckpointHash = deriveTargetFinalityCheckpointHash(
        targetFinalityCheckpointPayload,
    );
    const targetFinalityCheckpoint = {
        ...targetFinalityCheckpointPayload,
        targetFinalityCheckpointHash,
    };
    const inclusionProof = createInclusionProof(
        finalizedHead,
        'TopKEvaluationRecord',
        topKEvaluationRecordHash,
    );
    const witnessCheckpoints = witnessIdentities
        .slice(0, witnessCount)
        .map((witnessIdentity) =>
            createWitnessCheckpoint(
                witnessIdentity,
                finalizedHead.headHash,
                targetProposalHash,
                targetFinalityCheckpointHash,
                proposalPayload.electionManifestHash,
            ),
        );
    const payload = {
        objectType: 'TargetFinalityRecord',
        objectVersion: 1,
        ceremonyId,
        targetFinalityScope: 'target',
        targetProposalHash,
        targetFinalityCheckpoint,
        witnessPolicyHash,
        targetFinalityPolicyHash,
        inclusionProof,
        witnessCheckpoints,
    } satisfies Omit<TargetFinalityRecord, 'targetFinalityRecordHash'>;

    return {
        ...payload,
        targetFinalityRecordHash: deriveTargetFinalityRecordHash(payload),
    };
};

export const createBoardEvidence = (
    heads: readonly SignedBoardHead[],
): BoardConsistencyInput => ({
    ceremonyId,
    boardPolicyHash,
    signedBoardHeads: heads,
    expectedBoardPublicKeyHash: boardPublicKeyHash,
});
