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

export const verifyRequiredIncludedObjectPlacement = (input: {
    readonly expectedObjectType: InclusionProof['includedObjectType'];
    readonly headsByDigest: ReadonlyMap<ProtocolDigest, SignedBoardHead>;
    readonly objectBoardPosition: number;
    readonly objectBoardSequence: number;
    readonly objectDigest: ProtocolDigest;
    readonly proofByDigest: ReadonlyMap<ProtocolDigest, InclusionProof>;
    readonly rosterFreezeBoardSequence?: number;
}): readonly RefusalRecord[] => {
    const {
        expectedObjectType,
        headsByDigest,
        objectBoardPosition,
        objectBoardSequence,
        objectDigest,
        proofByDigest,
        rosterFreezeBoardSequence,
    } = input;
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
    const proofBindsExpectedObject =
        proof.includedObjectType === expectedObjectType &&
        proof.includedObjectDigest === objectDigest;

    if (!proofBindsExpectedObject) {
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

    if (!proofBindsExpectedObject) {
        return refusedObjects;
    }
    if (
        proof.boardSequence !== objectBoardSequence ||
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
        rosterFreezeBoardSequence !== undefined &&
        proof.boardSequence >= rosterFreezeBoardSequence
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
