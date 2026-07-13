import { verifySignedObjectSignature } from '@sealed-lattice/crypto';
import type {
    BoardConsistencyInput,
    ConflictingHeadEvidence,
    ProtocolHash,
    RefusalRecord,
    SignedBoardHead,
} from '@sealed-lattice/types';

import {
    buildBoardHeadMap,
    createRefusal,
    defaultSignedRootContextHash,
    isNonNegativeInteger,
} from '../common/verification-helpers.js';

import {
    deriveBoardHeadHash,
    deriveConflictingHeadEvidenceHash,
} from './hashes.js';

export const verifyBoardHead = (
    input: BoardConsistencyInput,
    head: SignedBoardHead,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedHeadHash = deriveBoardHeadHash(head);

    if (head.headHash !== expectedHeadHash) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'Board head hash does not match its canonical payload.',
                head.headHash,
                'BoardHead',
            ),
        );
    }
    if (head.ceremonyId !== input.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Board head ceremony does not match the verified ceremony.',
                head.headHash,
                'BoardHead',
            ),
        );
    }
    if (head.boardPolicyHash !== input.boardPolicyHash) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'Board head policy hash does not match the verified board policy.',
                head.headHash,
                'BoardHead',
            ),
        );
    }
    if (
        !isNonNegativeInteger(head.boardSequence) ||
        head.objectType !== 'BoardHead'
    ) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'Board head version and sequence must be canonical.',
                head.headHash,
                'BoardHead',
            ),
        );
    }
    if (head.previousHeadHash === null && head.boardSequence !== 0) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'Only the genesis board head may omit the previous head hash.',
                head.headHash,
                'BoardHead',
            ),
        );
    }
    if (head.previousHeadHash !== null && head.boardSequence === 0) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'The genesis board head must not bind a previous head hash.',
                head.headHash,
                'BoardHead',
            ),
        );
    }

    const signatureResult = verifySignedObjectSignature(head.signature, {
        objectType: 'BoardHead',
        signerRole: 'Board',
        signerIdentity: 'board',
        ceremonyId: input.ceremonyId,
        manifestHash: null,
        objectRoot: head.headHash,
        chunkMerkleRoot: null,
        boardHeadHash: null,
        recoveryEpoch: 0,
        deviceEpoch: 0,
        contextHash: defaultSignedRootContextHash,
        publicKeyHash: input.expectedBoardPublicKeyHash,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return refusedObjects;
};

export const isVerifiedAncestor = (
    ancestorHash: ProtocolHash,
    descendantHash: ProtocolHash,
    headsByHash: ReadonlyMap<ProtocolHash, SignedBoardHead>,
): boolean => {
    let currentHead = headsByHash.get(descendantHash);
    const visitedHeadHashes = new Set<ProtocolHash>();

    while (currentHead !== undefined) {
        if (currentHead.headHash === ancestorHash) {
            return true;
        }
        if (
            currentHead.previousHeadHash === null ||
            visitedHeadHashes.has(currentHead.headHash)
        ) {
            return false;
        }

        visitedHeadHashes.add(currentHead.headHash);
        currentHead = headsByHash.get(currentHead.previousHeadHash);
    }

    return false;
};

export const findConflictingHeads = (
    heads: readonly SignedBoardHead[],
): ConflictingHeadEvidence | undefined => {
    const headsByHash = buildBoardHeadMap(heads);

    for (let leftIndex = 0; leftIndex < heads.length; leftIndex += 1) {
        for (
            let rightIndex = leftIndex + 1;
            rightIndex < heads.length;
            rightIndex += 1
        ) {
            const leftHead = heads[leftIndex];
            const rightHead = heads[rightIndex];
            if (
                leftHead?.ceremonyId !== rightHead?.ceremonyId ||
                leftHead.boardPolicyHash !== rightHead.boardPolicyHash
            ) {
                continue;
            }
            const leftIsAncestor = isVerifiedAncestor(
                leftHead.headHash,
                rightHead.headHash,
                headsByHash,
            );
            const rightIsAncestor = isVerifiedAncestor(
                rightHead.headHash,
                leftHead.headHash,
                headsByHash,
            );

            if (!leftIsAncestor && !rightIsAncestor) {
                const evidence = {
                    ceremonyId: leftHead.ceremonyId,
                    boardPolicyHash: leftHead.boardPolicyHash,
                    leftBoardHeadHash: leftHead.headHash,
                    rightBoardHeadHash: rightHead.headHash,
                };

                return {
                    ...evidence,
                    evidenceHash: deriveConflictingHeadEvidenceHash(evidence),
                };
            }
        }
    }

    return undefined;
};

export const verifyPreviousHeadLinks = (
    heads: readonly SignedBoardHead[],
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const headsByHash = buildBoardHeadMap(heads);

    for (const head of heads) {
        if (head.previousHeadHash === null) {
            continue;
        }
        const previousHead = headsByHash.get(head.previousHeadHash);
        if (previousHead === undefined) {
            refusedObjects.push(
                createRefusal(
                    'BoardConsistencyFailure',
                    'Board head chain is missing a previous signed head.',
                    head.headHash,
                    'BoardHead',
                ),
            );
            continue;
        }
        if (previousHead.boardSequence + 1 !== head.boardSequence) {
            refusedObjects.push(
                createRefusal(
                    'BoardConsistencyFailure',
                    'Board head sequence must increase by one across the signed chain.',
                    head.headHash,
                    'BoardHead',
                ),
            );
        }
    }

    return refusedObjects;
};

export const verifySuppliedForkEvidence = (
    input: BoardConsistencyInput,
    evidence: ConflictingHeadEvidence,
    headsByHash: ReadonlyMap<ProtocolHash, SignedBoardHead>,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedHash = deriveConflictingHeadEvidenceHash({
        boardPolicyHash: evidence.boardPolicyHash,
        ceremonyId: evidence.ceremonyId,
        equivocatingWitnessIdentities:
            evidence.equivocatingWitnessIdentities ?? [],
        leftBoardHeadHash: evidence.leftBoardHeadHash,
        rightBoardHeadHash: evidence.rightBoardHeadHash,
    });

    if (evidence.evidenceHash !== expectedHash) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'Supplied fork evidence hash does not match its canonical payload.',
                evidence.evidenceHash,
            ),
        );
    }
    if (
        evidence.ceremonyId !== input.ceremonyId ||
        evidence.boardPolicyHash !== input.boardPolicyHash
    ) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'Supplied fork evidence does not match the verified ceremony and board policy.',
                evidence.evidenceHash,
            ),
        );
    }
    const leftHead = headsByHash.get(evidence.leftBoardHeadHash);
    const rightHead = headsByHash.get(evidence.rightBoardHeadHash);
    if (leftHead === undefined || rightHead === undefined) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'Supplied fork evidence must reference known signed board heads.',
                evidence.evidenceHash,
            ),
        );
        return refusedObjects;
    }
    if (leftHead.headHash === rightHead.headHash) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'Supplied fork evidence must reference two distinct board heads.',
                evidence.evidenceHash,
            ),
        );
        return refusedObjects;
    }

    const leftIsAncestor = isVerifiedAncestor(
        leftHead.headHash,
        rightHead.headHash,
        headsByHash,
    );
    const rightIsAncestor = isVerifiedAncestor(
        rightHead.headHash,
        leftHead.headHash,
        headsByHash,
    );
    if (leftIsAncestor || rightIsAncestor) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'Supplied fork evidence references compatible board heads.',
                evidence.evidenceHash,
            ),
        );
    }

    return refusedObjects;
};
