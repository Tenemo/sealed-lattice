import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type {
    BoardConsistencyInput,
    InclusionProof,
    SignedBoardHead,
    TargetFinalityRecord,
    TargetProposal,
    WitnessCheckpoint,
} from '@sealed-lattice/types';

import {
    boardPolicyHash,
    boardPublicKeyHash,
    ceremonyId,
    createKeyFixture,
    deriveFixtureHash,
    createSignature,
    defaultThresholdParametersHash,
    defaultEvaluatorReplayRecordHash,
    manifestOpaqueBindings,
    targetFinalityPolicyHash,
    witnessIdentities,
    witnessPolicyHash,
    witnessPublicKeyHashes,
} from './election-foundation-fixture-constants';

import {
    deriveBoardEntryMerklePath,
    deriveBoardEntryHash,
    deriveBoardHeadHash,
    deriveBoardRootHash,
    deriveInclusionProofHash,
} from '#packages/protocol/src/board/index';
import {
    deriveTargetFinalityCheckpointHash,
    deriveTargetFinalityRecordHash,
    deriveTargetProposalHash,
    deriveWitnessCheckpointHash,
} from '#packages/protocol/src/finality/index';

export const createBoardHead = (
    boardSequence: number,
    previousHeadHash: string | null,
    branchName = 'main',
    boardEntryHashes?: readonly string[],
): SignedBoardHead => {
    const resolvedBoardEntryHashes = boardEntryHashes ?? [
        deriveCanonicalObjectHash({
            objectType: 'BoardEntryFiller',
            branchName,
            marker: 'empty-board-head',
            boardSequence,
        }),
    ];
    const unsignedHead: SignedBoardHead = {
        objectType: 'BoardHead',
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
                : deriveCanonicalObjectHash({
                      objectType: 'BoardEntryFiller',
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
                ? deriveCanonicalObjectHash({
                      objectType: 'BoardEntryFiller',
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
    evaluatorReplayRecordHash = defaultEvaluatorReplayRecordHash,
): SignedBoardHead =>
    createBoardHeadWithObjects(
        boardSequence,
        previousHeadHash,
        [
            {
                objectType: 'EvaluatorReplayRecord',
                objectHash: evaluatorReplayRecordHash,
                boardPosition: 0,
            },
        ],
        branchName,
    ).head;

export const createWitnessCheckpoint = (
    witnessIdentity: string,
    finalizedBoardHeadHash: string,
    targetProposalHash = deriveCanonicalObjectHash({
        objectType: 'WitnessCheckpointProposalPlaceholder',
        finalizedBoardHeadHash,
        witnessIdentity,
    }),
    targetFinalityCheckpointHash = deriveCanonicalObjectHash({
        objectType: 'WitnessCheckpointFinalityPlaceholder',
        finalizedBoardHeadHash,
        targetProposalHash,
        witnessIdentity,
    }),
    electionManifestHash: string | null = null,
    overrides: Partial<WitnessCheckpoint> = {},
): WitnessCheckpoint => {
    const checkpointPayload = {
        objectType: 'WitnessCheckpoint',
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
    evaluatorReplayRecordHash = defaultEvaluatorReplayRecordHash,
    witnessCount = 5,
    proposalOverrides: Partial<Omit<TargetProposal, 'targetProposalHash'>> = {},
): TargetFinalityRecord => {
    const proposalPayload = {
        ceremonyId,
        electionManifestHash: deriveCanonicalObjectHash({
            objectType: 'FixtureManifestPlaceholder',
            ceremonyId,
            marker: 'default-manifest',
        }),
        thresholdParametersHash: defaultThresholdParametersHash,
        evaluatorReplayContextHash: deriveCanonicalObjectHash({
            objectType: 'FixtureEvaluatorReplayContextPlaceholder',
            ceremonyId,
            marker: 'direct-evaluator-replay',
        }),
        evaluatorReplayRecordHash,
        encryptedBallotAggregateHash: deriveCanonicalObjectHash({
            objectType: 'FixtureCiphertextRootPlaceholder',
            ceremonyId,
            marker: 'direct-encrypted-ballot-aggregate',
        }),
        targetCiphertextHash: deriveCanonicalObjectHash({
            objectType: 'FixtureCiphertextRootPlaceholder',
            ceremonyId,
            marker: 'direct-target-ciphertext',
        }),
        targetLayoutHash: deriveCanonicalObjectHash({
            objectType: 'FixtureTargetLayoutPlaceholder',
            layout: 'direct-sparse-target-layout',
        }),
        bgvParametersHash: manifestOpaqueBindings.bgvParametersHash,
        targetFinalityPolicyHash,
        topOptionCount: 2,
        tiePolicyHash: deriveFixtureHash('fixture-tie-policy', {
            tiePolicy: 'HigherScoreThenLowerOptionIndex',
        }),
        ...proposalOverrides,
    } satisfies Omit<TargetProposal, 'targetProposalHash'>;
    const targetProposalHash = deriveTargetProposalHash(proposalPayload);
    const targetFinalityCheckpointPayload = {
        ...proposalPayload,
        targetProposalHash,
        objectType: 'TargetFinalityCheckpoint',
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
        'EvaluatorReplayRecord',
        evaluatorReplayRecordHash,
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
