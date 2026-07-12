import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type {
    BoardConsistencyInput,
    InclusionProof,
    SignedBoardHead,
} from '@sealed-lattice/types';

import {
    boardPolicyHash,
    boardPublicKeyHash,
    ceremonyId,
    createSignature,
} from './election-foundation-fixture-constants';

import {
    deriveBoardEntryMerklePath,
    deriveBoardEntryHash,
    deriveBoardHeadHash,
    deriveBoardRootHash,
    deriveInclusionProofHash,
} from '#packages/protocol/src/board/index';

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

export const createBoardEvidence = (
    heads: readonly SignedBoardHead[],
): BoardConsistencyInput => ({
    ceremonyId,
    boardPolicyHash,
    signedBoardHeads: heads,
    expectedBoardPublicKeyHash: boardPublicKeyHash,
});
