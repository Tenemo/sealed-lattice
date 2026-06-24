import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type {
    BoardEntryMerklePathStep,
    ConflictingHeadEvidence,
    InclusionProof,
    ProtocolHash,
    ProtocolObjectType,
    SignedBoardHead,
} from '@sealed-lattice/types';

import {
    isRecord,
    isNonNegativeInteger,
} from '../common/verification-helpers.js';

type BoardEntryHashInput = {
    readonly boardPosition: number;
    readonly includedObjectType: ProtocolObjectType;
    readonly includedObjectHash: ProtocolHash;
};

export const deriveBoardEntryHash = (
    entry: BoardEntryHashInput,
): ProtocolHash =>
    deriveProtocolHash('BoardEntryHash', {
        boardPosition: entry.boardPosition,
        includedObjectHash: entry.includedObjectHash,
        includedObjectType: entry.includedObjectType,
    });

// Two distinct board-root models share the 'BoardRootHash' namespace: this
// structured Merkle-tree model (leaf/branch/root nodeKind variants, below) and
// the flat boardEntryHashes-list model (deriveBoardEntryListRootHash). The
// presence of `nodeKind` vs the list shape disambiguates them in the preimage.
export const deriveBoardLeafNodeHash = (
    boardPosition: number,
    boardEntryHash: ProtocolHash,
): ProtocolHash =>
    deriveProtocolHash('BoardRootHash', {
        nodeKind: 'BoardEntryLeaf',
        boardPosition,
        boardEntryHash,
    });

export const deriveBoardBranchNodeHash = (
    leftNodeHash: ProtocolHash,
    rightNodeHash: ProtocolHash,
): ProtocolHash =>
    deriveProtocolHash('BoardRootHash', {
        nodeKind: 'BoardEntryBranch',
        leftNodeHash,
        rightNodeHash,
    });

export const deriveBoardRootFromNodeHash = (
    boardEntryCount: number,
    rootNodeHash: ProtocolHash | null,
): ProtocolHash =>
    deriveProtocolHash('BoardRootHash', {
        nodeKind: 'BoardEntryRoot',
        boardEntryCount,
        rootNodeHash,
    });

const deriveNextBoardMerkleLevel = (
    levelHashes: readonly ProtocolHash[],
): readonly ProtocolHash[] => {
    const nextLevelHashes: ProtocolHash[] = [];

    for (let levelIndex = 0; levelIndex < levelHashes.length; levelIndex += 2) {
        const leftNodeHash = levelHashes[levelIndex];
        const rightNodeHash = levelHashes[levelIndex + 1];
        if (leftNodeHash === undefined) {
            continue;
        }
        nextLevelHashes.push(
            rightNodeHash === undefined
                ? leftNodeHash
                : deriveBoardBranchNodeHash(leftNodeHash, rightNodeHash),
        );
    }

    return nextLevelHashes;
};

// Flat board-root model: hashes the whole boardEntryHashes list directly (no
// nodeKind). Shares the 'BoardRootHash' namespace with the structured tree
// model above; the differing payload shape keeps the two preimages disjoint.
export const deriveBoardEntryListRootHash = (
    boardEntryHashes: readonly ProtocolHash[],
): ProtocolHash => deriveProtocolHash('BoardRootHash', { boardEntryHashes });

export const deriveBoardRootHash = (
    boardEntryHashes: readonly ProtocolHash[],
): ProtocolHash => {
    if (boardEntryHashes.length === 0) {
        return deriveBoardRootFromNodeHash(0, null);
    }

    let levelHashes = boardEntryHashes.map((boardEntryHash, boardPosition) =>
        deriveBoardLeafNodeHash(boardPosition, boardEntryHash),
    );
    while (levelHashes.length > 1) {
        levelHashes = [...deriveNextBoardMerkleLevel(levelHashes)];
    }

    return deriveBoardRootFromNodeHash(
        boardEntryHashes.length,
        levelHashes[0] ?? null,
    );
};

export const deriveBoardEntryMerklePath = (
    boardEntryHashes: readonly ProtocolHash[],
    boardPosition: number,
): readonly BoardEntryMerklePathStep[] => {
    if (
        !isNonNegativeInteger(boardPosition) ||
        boardPosition >= boardEntryHashes.length
    ) {
        throw new RangeError(
            'Board-entry Merkle path requires an included board position.',
        );
    }

    const path: BoardEntryMerklePathStep[] = [];
    let levelHashes = boardEntryHashes.map((boardEntryHash, entryIndex) =>
        deriveBoardLeafNodeHash(entryIndex, boardEntryHash),
    );
    let levelIndex = boardPosition;

    while (levelHashes.length > 1) {
        if (levelIndex % 2 === 0) {
            const siblingHash = levelHashes[levelIndex + 1];
            if (siblingHash !== undefined) {
                path.push({
                    siblingPosition: 'Right',
                    siblingHash,
                });
            }
        } else {
            const siblingHash = levelHashes[levelIndex - 1];
            if (siblingHash === undefined) {
                throw new RangeError(
                    'Board-entry Merkle path has no left sibling.',
                );
            }
            path.push({
                siblingPosition: 'Left',
                siblingHash,
            });
        }
        levelHashes = [...deriveNextBoardMerkleLevel(levelHashes)];
        levelIndex = Math.floor(levelIndex / 2);
    }

    return path;
};

export const deriveBoardHeadHash = (head: SignedBoardHead): ProtocolHash =>
    deriveProtocolHash('BoardHeadHash', {
        boardPolicyHash: head.boardPolicyHash,
        boardRoot: head.boardRoot,
        boardSequence: head.boardSequence,
        ceremonyId: head.ceremonyId,
        objectType: head.objectType,
        objectVersion: head.objectVersion,
        previousHeadHash: head.previousHeadHash,
    });

export const inclusionProofUsesMerklePath = (
    inclusionProof: Omit<InclusionProof, 'inclusionProofHash'>,
): boolean =>
    inclusionProof.boardEntryCount !== undefined ||
    inclusionProof.boardEntryMerklePath !== undefined;

const isBoardEntryMerklePathStep = (
    value: unknown,
): value is BoardEntryMerklePathStep => {
    if (!isRecord(value)) {
        return false;
    }

    return (
        (value.siblingPosition === 'Left' ||
            value.siblingPosition === 'Right') &&
        typeof value.siblingHash === 'string'
    );
};

export const isBoardEntryMerklePath = (
    value: unknown,
): value is readonly BoardEntryMerklePathStep[] =>
    Array.isArray(value) && value.every(isBoardEntryMerklePathStep);

export const deriveInclusionProofHash = (
    inclusionProof: Omit<InclusionProof, 'inclusionProofHash'>,
): ProtocolHash => {
    const sharedPayload = {
        boardHeadHash: inclusionProof.boardHeadHash,
        boardEntryHash: inclusionProof.boardEntryHash,
        boardPosition: inclusionProof.boardPosition,
        boardRoot: inclusionProof.boardRoot,
        boardSequence: inclusionProof.boardSequence,
        includedObjectHash: inclusionProof.includedObjectHash,
        includedObjectType: inclusionProof.includedObjectType,
    };

    return deriveProtocolHash(
        'InclusionProofHash',
        inclusionProofUsesMerklePath(inclusionProof)
            ? {
                  ...sharedPayload,
                  boardEntryCount: inclusionProof.boardEntryCount ?? null,
                  boardEntryMerklePath:
                      inclusionProof.boardEntryMerklePath ?? [],
              }
            : {
                  ...sharedPayload,
                  boardEntryHashes: inclusionProof.boardEntryHashes ?? [],
              },
    );
};

export const deriveConflictingHeadEvidenceHash = (
    evidence: Omit<ConflictingHeadEvidence, 'evidenceHash'>,
): ProtocolHash =>
    deriveProtocolHash('ConflictingHeadEvidenceHash', {
        boardPolicyHash: evidence.boardPolicyHash,
        ceremonyId: evidence.ceremonyId,
        equivocatingWitnessIdentities:
            evidence.equivocatingWitnessIdentities ?? [],
        leftBoardHeadHash: evidence.leftBoardHeadHash,
        purpose: 'board-conflicting-head-evidence-v1',
        rightBoardHeadHash: evidence.rightBoardHeadHash,
        targetFinalityScope: evidence.targetFinalityScope ?? null,
    });
