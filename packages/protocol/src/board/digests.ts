import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BoardEntryMerklePathStep,
    ConflictingHeadEvidence,
    InclusionProof,
    ProtocolDigest,
    ProtocolObjectType,
    SignedBoardHead,
} from '@sealed-lattice/types';

import { isNonNegativeInteger } from '../common/verification-helpers.js';

type BoardEntryDigestInput = {
    readonly boardPosition: number;
    readonly includedObjectType: ProtocolObjectType;
    readonly includedObjectDigest: ProtocolDigest;
};

export const deriveBoardEntryDigest = (
    entry: BoardEntryDigestInput,
): ProtocolDigest =>
    deriveProtocolDigest('BoardEntryDigest', {
        boardPosition: entry.boardPosition,
        includedObjectDigest: entry.includedObjectDigest,
        includedObjectType: entry.includedObjectType,
    });

export const deriveBoardLeafNodeDigest = (
    boardPosition: number,
    boardEntryDigest: ProtocolDigest,
): ProtocolDigest =>
    deriveProtocolDigest('BoardRootDigest', {
        nodeKind: 'BoardEntryLeaf',
        boardPosition,
        boardEntryDigest,
    });

export const deriveBoardBranchNodeDigest = (
    leftNodeDigest: ProtocolDigest,
    rightNodeDigest: ProtocolDigest,
): ProtocolDigest =>
    deriveProtocolDigest('BoardRootDigest', {
        nodeKind: 'BoardEntryBranch',
        leftNodeDigest,
        rightNodeDigest,
    });

export const deriveBoardRootFromNodeDigest = (
    boardEntryCount: number,
    rootNodeDigest: ProtocolDigest | null,
): ProtocolDigest =>
    deriveProtocolDigest('BoardRootDigest', {
        nodeKind: 'BoardEntryRoot',
        boardEntryCount,
        rootNodeDigest,
    });

const deriveNextBoardMerkleLevel = (
    levelDigests: readonly ProtocolDigest[],
): readonly ProtocolDigest[] => {
    const nextLevelDigests: ProtocolDigest[] = [];

    for (
        let levelIndex = 0;
        levelIndex < levelDigests.length;
        levelIndex += 2
    ) {
        const leftNodeDigest = levelDigests[levelIndex];
        const rightNodeDigest = levelDigests[levelIndex + 1];
        if (leftNodeDigest === undefined) {
            continue;
        }
        nextLevelDigests.push(
            rightNodeDigest === undefined
                ? leftNodeDigest
                : deriveBoardBranchNodeDigest(leftNodeDigest, rightNodeDigest),
        );
    }

    return nextLevelDigests;
};

export const deriveBoardEntryListRootDigest = (
    boardEntryDigests: readonly ProtocolDigest[],
): ProtocolDigest =>
    deriveProtocolDigest('BoardRootDigest', { boardEntryDigests });

export const deriveBoardRootDigest = (
    boardEntryDigests: readonly ProtocolDigest[],
): ProtocolDigest => {
    if (boardEntryDigests.length === 0) {
        return deriveBoardRootFromNodeDigest(0, null);
    }

    let levelDigests = boardEntryDigests.map(
        (boardEntryDigest, boardPosition) =>
            deriveBoardLeafNodeDigest(boardPosition, boardEntryDigest),
    );
    while (levelDigests.length > 1) {
        levelDigests = [...deriveNextBoardMerkleLevel(levelDigests)];
    }

    return deriveBoardRootFromNodeDigest(
        boardEntryDigests.length,
        levelDigests[0] ?? null,
    );
};

export const deriveBoardEntryMerklePath = (
    boardEntryDigests: readonly ProtocolDigest[],
    boardPosition: number,
): readonly BoardEntryMerklePathStep[] => {
    if (
        !isNonNegativeInteger(boardPosition) ||
        boardPosition >= boardEntryDigests.length
    ) {
        throw new RangeError(
            'Board-entry Merkle path requires an included board position.',
        );
    }

    const path: BoardEntryMerklePathStep[] = [];
    let levelDigests = boardEntryDigests.map((boardEntryDigest, entryIndex) =>
        deriveBoardLeafNodeDigest(entryIndex, boardEntryDigest),
    );
    let levelIndex = boardPosition;

    while (levelDigests.length > 1) {
        if (levelIndex % 2 === 0) {
            const siblingDigest = levelDigests[levelIndex + 1];
            if (siblingDigest !== undefined) {
                path.push({
                    siblingPosition: 'Right',
                    siblingDigest,
                });
            }
        } else {
            const siblingDigest = levelDigests[levelIndex - 1];
            if (siblingDigest === undefined) {
                throw new RangeError(
                    'Board-entry Merkle path has no left sibling.',
                );
            }
            path.push({
                siblingPosition: 'Left',
                siblingDigest,
            });
        }
        levelDigests = [...deriveNextBoardMerkleLevel(levelDigests)];
        levelIndex = Math.floor(levelIndex / 2);
    }

    return path;
};

export const deriveBoardHeadDigest = (head: SignedBoardHead): ProtocolDigest =>
    deriveProtocolDigest('BoardHeadDigest', {
        boardPolicyDigest: head.boardPolicyDigest,
        boardRoot: head.boardRoot,
        boardSequence: head.boardSequence,
        ceremonyId: head.ceremonyId,
        objectType: head.objectType,
        objectVersion: head.objectVersion,
        previousHeadDigest: head.previousHeadDigest,
    });

export const inclusionProofUsesMerklePath = (
    inclusionProof: Omit<InclusionProof, 'inclusionProofDigest'>,
): boolean =>
    inclusionProof.boardEntryCount !== undefined ||
    inclusionProof.boardEntryMerklePath !== undefined;

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
    typeof value === 'object' && value !== null;

const isBoardEntryMerklePathStep = (
    value: unknown,
): value is BoardEntryMerklePathStep => {
    if (!isRecord(value)) {
        return false;
    }

    return (
        (value.siblingPosition === 'Left' ||
            value.siblingPosition === 'Right') &&
        typeof value.siblingDigest === 'string'
    );
};

export const isBoardEntryMerklePath = (
    value: unknown,
): value is readonly BoardEntryMerklePathStep[] =>
    Array.isArray(value) && value.every(isBoardEntryMerklePathStep);

export const deriveInclusionProofDigest = (
    inclusionProof: Omit<InclusionProof, 'inclusionProofDigest'>,
): ProtocolDigest => {
    const sharedPayload = {
        boardHeadDigest: inclusionProof.boardHeadDigest,
        boardEntryDigest: inclusionProof.boardEntryDigest,
        boardPosition: inclusionProof.boardPosition,
        boardRoot: inclusionProof.boardRoot,
        boardSequence: inclusionProof.boardSequence,
        includedObjectDigest: inclusionProof.includedObjectDigest,
        includedObjectType: inclusionProof.includedObjectType,
    };

    return deriveProtocolDigest(
        'InclusionProofDigest',
        inclusionProofUsesMerklePath(inclusionProof)
            ? {
                  ...sharedPayload,
                  boardEntryCount: inclusionProof.boardEntryCount ?? null,
                  boardEntryMerklePath:
                      inclusionProof.boardEntryMerklePath ?? [],
              }
            : {
                  ...sharedPayload,
                  boardEntryDigests: inclusionProof.boardEntryDigests ?? [],
              },
    );
};

export const deriveConflictingHeadEvidenceDigest = (
    evidence: Omit<ConflictingHeadEvidence, 'evidenceDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('ConflictingHeadEvidenceDigest', {
        boardPolicyDigest: evidence.boardPolicyDigest,
        ceremonyId: evidence.ceremonyId,
        equivocatingWitnessIdentities:
            evidence.equivocatingWitnessIdentities ?? [],
        leftBoardHeadDigest: evidence.leftBoardHeadDigest,
        rightBoardHeadDigest: evidence.rightBoardHeadDigest,
        targetFinalityScope: evidence.targetFinalityScope ?? null,
    });
