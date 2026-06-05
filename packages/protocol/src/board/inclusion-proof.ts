import type {
    InclusionProof,
    ProtocolHash,
    RefusalRecord,
    SignedBoardHead,
} from '@sealed-lattice/types';

import {
    createRefusal,
    isNonNegativeInteger,
} from '../common/verification-helpers.js';

import {
    deriveBoardBranchNodeHash,
    deriveBoardEntryHash,
    deriveBoardEntryListRootHash,
    deriveBoardLeafNodeHash,
    deriveBoardRootFromNodeHash,
    deriveInclusionProofHash,
    inclusionProofUsesMerklePath,
    isBoardEntryMerklePath,
} from './hashes.js';

const deriveBoardRootFromMerkleInclusionProof = (
    inclusionProof: InclusionProof,
): ProtocolHash | undefined => {
    const { boardEntryCount, boardEntryMerklePath } = inclusionProof;
    if (
        typeof boardEntryCount !== 'number' ||
        !isNonNegativeInteger(boardEntryCount) ||
        boardEntryCount === 0 ||
        !isNonNegativeInteger(inclusionProof.boardPosition) ||
        inclusionProof.boardPosition >= boardEntryCount ||
        !isBoardEntryMerklePath(boardEntryMerklePath)
    ) {
        return undefined;
    }

    let computedNodeHash = deriveBoardLeafNodeHash(
        inclusionProof.boardPosition,
        inclusionProof.boardEntryHash,
    );
    let levelIndex = inclusionProof.boardPosition;
    let levelWidth = boardEntryCount;
    let pathStepIndex = 0;

    while (levelWidth > 1) {
        const pathStep = boardEntryMerklePath[pathStepIndex];
        if (levelIndex % 2 === 0) {
            if (levelIndex + 1 < levelWidth) {
                if (
                    pathStep?.siblingPosition !== 'Right' ||
                    typeof pathStep.siblingHash !== 'string'
                ) {
                    return undefined;
                }
                computedNodeHash = deriveBoardBranchNodeHash(
                    computedNodeHash,
                    pathStep.siblingHash,
                );
                pathStepIndex += 1;
            }
        } else {
            if (
                pathStep?.siblingPosition !== 'Left' ||
                typeof pathStep.siblingHash !== 'string'
            ) {
                return undefined;
            }
            computedNodeHash = deriveBoardBranchNodeHash(
                pathStep.siblingHash,
                computedNodeHash,
            );
            pathStepIndex += 1;
        }

        levelIndex = Math.floor(levelIndex / 2);
        levelWidth = Math.ceil(levelWidth / 2);
    }

    if (pathStepIndex !== boardEntryMerklePath.length) {
        return undefined;
    }

    return deriveBoardRootFromNodeHash(boardEntryCount, computedNodeHash);
};

export const verifyInclusionProof = (
    inclusionProof: InclusionProof,
    headsByHash: ReadonlyMap<ProtocolHash, SignedBoardHead>,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const head = headsByHash.get(inclusionProof.boardHeadHash);
    const expectedBoardEntryHash = deriveBoardEntryHash({
        boardPosition: inclusionProof.boardPosition,
        includedObjectHash: inclusionProof.includedObjectHash,
        includedObjectType: inclusionProof.includedObjectType,
    });
    const usesMerklePath = inclusionProofUsesMerklePath(inclusionProof);
    const usesBoardEntryHashList =
        inclusionProof.boardEntryHashes !== undefined;
    const expectedBoardRoot = usesMerklePath
        ? deriveBoardRootFromMerkleInclusionProof(inclusionProof)
        : Array.isArray(inclusionProof.boardEntryHashes)
          ? deriveBoardEntryListRootHash(inclusionProof.boardEntryHashes)
          : undefined;
    const expectedHash = deriveInclusionProofHash({
        boardHeadHash: inclusionProof.boardHeadHash,
        boardEntryHash: inclusionProof.boardEntryHash,
        boardEntryCount: inclusionProof.boardEntryCount,
        boardEntryMerklePath: inclusionProof.boardEntryMerklePath,
        boardEntryHashes: inclusionProof.boardEntryHashes,
        boardPosition: inclusionProof.boardPosition,
        boardRoot: inclusionProof.boardRoot,
        boardSequence: inclusionProof.boardSequence,
        includedObjectHash: inclusionProof.includedObjectHash,
        includedObjectType: inclusionProof.includedObjectType,
    });

    if (inclusionProof.inclusionProofHash !== expectedHash) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof hash does not match its canonical payload.',
                inclusionProof.inclusionProofHash,
            ),
        );
    }
    if (inclusionProof.boardEntryHash !== expectedBoardEntryHash) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof board-entry hash does not match its canonical payload.',
                inclusionProof.inclusionProofHash,
            ),
        );
    }
    if (usesMerklePath && usesBoardEntryHashList) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof must use exactly one board inclusion witness model.',
                inclusionProof.inclusionProofHash,
            ),
        );
    }
    if (!usesMerklePath && !usesBoardEntryHashList) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof must include a board inclusion witness.',
                inclusionProof.inclusionProofHash,
            ),
        );
    }
    if (expectedBoardRoot === undefined) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof board witness is malformed.',
                inclusionProof.inclusionProofHash,
            ),
        );
    } else if (inclusionProof.boardRoot !== expectedBoardRoot) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof board root does not match its board inclusion witness.',
                inclusionProof.inclusionProofHash,
            ),
        );
    }
    if (head === undefined) {
        refusedObjects.push(
            createRefusal(
                'UnknownBoardHead',
                'Inclusion proof references an unknown signed board head.',
                inclusionProof.includedObjectHash,
                inclusionProof.includedObjectType,
            ),
        );
    } else if (head.boardSequence !== inclusionProof.boardSequence) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof sequence does not match the board head.',
                inclusionProof.inclusionProofHash,
            ),
        );
    } else if (head.boardRoot !== inclusionProof.boardRoot) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof board root does not match the signed board head.',
                inclusionProof.inclusionProofHash,
            ),
        );
    }
    if (!isNonNegativeInteger(inclusionProof.boardPosition)) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof board position must be a non-negative integer.',
                inclusionProof.inclusionProofHash,
            ),
        );
    } else if (
        Array.isArray(inclusionProof.boardEntryHashes) &&
        inclusionProof.boardEntryHashes[inclusionProof.boardPosition] !==
            inclusionProof.boardEntryHash
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof board entry is not present at the claimed board position.',
                inclusionProof.inclusionProofHash,
            ),
        );
    }

    return refusedObjects;
};
