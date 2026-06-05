import type {
    InclusionProof,
    ProtocolHash,
    RefusalRecord,
    SignedBoardHead,
} from '@sealed-lattice/types';

import { verifyInclusionProof } from '../board/inclusion-proof.js';
import { createRefusal } from '../common/verification-helpers.js';

export const mapInclusionProofsByObjectHash = (
    inclusionProofs: readonly InclusionProof[],
): Map<ProtocolHash, InclusionProof> =>
    new Map(inclusionProofs.map((proof) => [proof.includedObjectHash, proof]));

export const verifyRequiredIncludedObjectPlacement = (input: {
    readonly expectedObjectType: InclusionProof['includedObjectType'];
    readonly headsByHash: ReadonlyMap<ProtocolHash, SignedBoardHead>;
    readonly objectBoardPosition: number;
    readonly objectBoardSequence: number;
    readonly objectHash: ProtocolHash;
    readonly proofByHash: ReadonlyMap<ProtocolHash, InclusionProof>;
    readonly rosterFreezeBoardSequence?: number;
}): readonly RefusalRecord[] => {
    const {
        expectedObjectType,
        headsByHash,
        objectBoardPosition,
        objectBoardSequence,
        objectHash,
        proofByHash,
        rosterFreezeBoardSequence,
    } = input;
    const proof = proofByHash.get(objectHash);
    if (proof === undefined) {
        return [
            createRefusal(
                'InclusionProofInvalid',
                'Required transcript object has no supplied board inclusion proof.',
                objectHash,
                expectedObjectType,
            ),
        ];
    }
    const refusedObjects: RefusalRecord[] = [];
    const proofBindsExpectedObject =
        proof.includedObjectType === expectedObjectType &&
        proof.includedObjectHash === objectHash;

    if (!proofBindsExpectedObject) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Board inclusion proof does not bind the expected object.',
                proof.inclusionProofHash,
                expectedObjectType,
            ),
        );
    }
    refusedObjects.push(...verifyInclusionProof(proof, headsByHash));

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
                objectHash,
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
                objectHash,
                expectedObjectType,
            ),
        );
    }

    return refusedObjects;
};
