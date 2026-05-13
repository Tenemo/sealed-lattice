import type {
    InclusionProof,
    ProtocolDigest,
    RefusalRecord,
    SignedBoardHead,
} from '@sealed-lattice/types';

import { verifyInclusionProof } from '../board/index.js';
import { createRefusal } from '../common/verification-helpers.js';

export const mapInclusionProofsByObjectDigest = (
    inclusionProofs: readonly InclusionProof[],
): Map<ProtocolDigest, InclusionProof> =>
    new Map(
        inclusionProofs.map((proof) => [proof.includedObjectDigest, proof]),
    );

export const verifyRequiredInclusionProof = (
    proofByDigest: ReadonlyMap<ProtocolDigest, InclusionProof>,
    objectDigest: ProtocolDigest,
    expectedObjectType: InclusionProof['includedObjectType'],
    headsByDigest: ReadonlyMap<ProtocolDigest, SignedBoardHead>,
): readonly RefusalRecord[] => {
    const proof = proofByDigest.get(objectDigest);
    if (proof === undefined) {
        return [
            createRefusal(
                'InclusionProofInvalid',
                'Required transcript object has no supplied board inclusion proof.',
                objectDigest,
                expectedObjectType,
            ),
        ];
    }
    const refusedObjects: RefusalRecord[] = [];
    if (
        proof.includedObjectType !== expectedObjectType ||
        proof.includedObjectDigest !== objectDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Board inclusion proof does not bind the expected object.',
                proof.inclusionProofDigest,
                expectedObjectType,
            ),
        );
    }
    refusedObjects.push(...verifyInclusionProof(proof, headsByDigest));

    return refusedObjects;
};

export const verifyIncludedBoardPlacement = (
    proofByDigest: ReadonlyMap<ProtocolDigest, InclusionProof>,
    objectDigest: ProtocolDigest,
    expectedObjectType: InclusionProof['includedObjectType'],
    objectBoardSeq: number,
    objectBoardPosition: number,
    rosterFreezeBoardSeq: number | undefined,
): readonly RefusalRecord[] => {
    const proof = proofByDigest.get(objectDigest);
    if (proof === undefined) {
        return [];
    }
    const refusedObjects: RefusalRecord[] = [];

    if (
        proof.includedObjectType !== expectedObjectType ||
        proof.includedObjectDigest !== objectDigest
    ) {
        return refusedObjects;
    }
    if (
        proof.boardSeq !== objectBoardSeq ||
        proof.boardPosition !== objectBoardPosition
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Transcript object board position must match its inclusion proof.',
                objectDigest,
                expectedObjectType,
            ),
        );
    }
    if (
        rosterFreezeBoardSeq !== undefined &&
        proof.boardSeq >= rosterFreezeBoardSeq
    ) {
        refusedObjects.push(
            createRefusal(
                'LateRegistration',
                'Roster object inclusion must appear before the roster freeze board sequence.',
                objectDigest,
                expectedObjectType,
            ),
        );
    }

    return refusedObjects;
};
