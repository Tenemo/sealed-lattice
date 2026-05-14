import type {
    BoardConsistencyInput,
    BoardConsistencyVerification,
    InclusionProof,
    ProtocolDigest,
    RefusalRecord,
    SignedBoardHead,
} from '@sealed-lattice/types';

import { buildBoardHeadMap } from '../common/verification-helpers.js';

import { verifyBoardConsistency, verifyInclusionProof } from './index.js';

type BoardInclusionEvidence = {
    readonly boardResult: BoardConsistencyVerification;
    readonly headsByDigest: ReadonlyMap<ProtocolDigest, SignedBoardHead>;
    readonly refusedObjects: RefusalRecord[];
};

export const collectBoardInclusionEvidence = (input: {
    readonly boardEvidence: BoardConsistencyInput;
    readonly inclusionProof: InclusionProof;
    readonly objectRefusals: readonly RefusalRecord[];
}): BoardInclusionEvidence => {
    const boardResult = verifyBoardConsistency(input.boardEvidence);
    const headsByDigest = buildBoardHeadMap(
        input.boardEvidence.signedBoardHeads,
    );

    return {
        boardResult,
        headsByDigest,
        refusedObjects: [
            ...boardResult.refusedObjects,
            ...input.objectRefusals,
            ...verifyInclusionProof(input.inclusionProof, headsByDigest),
        ],
    };
};
