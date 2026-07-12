import {
    verifySignedObjectSignature,
    type SignatureExpectation,
} from '@sealed-lattice/crypto';
import type {
    BoardConsistencyInput,
    BoardConsistencyVerification,
    InclusionProof,
    ProtocolHash,
    ProtocolSignatureEnvelope,
    RefusalRecord,
    SignedBoardHead,
} from '@sealed-lattice/types';

import { buildBoardHeadMap } from '../common/verification-helpers.js';

import { verifyBoardConsistency } from './consistency.js';
import { verifyInclusionProof } from './inclusion-proof.js';

type BoardEvidence = {
    readonly boardResult: BoardConsistencyVerification;
    readonly headsByHash: ReadonlyMap<ProtocolHash, SignedBoardHead>;
};

type BoardInclusionEvidence = BoardEvidence & {
    readonly refusedObjects: RefusalRecord[];
};

type SignedBoardShellVerificationBase = {
    readonly isValid: boolean;
    readonly refusedObjects: readonly RefusalRecord[];
    readonly forkEvidence: BoardConsistencyVerification['forkEvidence'];
};

export const collectBoardEvidence = (
    boardEvidence: BoardConsistencyInput,
): BoardEvidence => ({
    boardResult: verifyBoardConsistency(boardEvidence),
    headsByHash: buildBoardHeadMap(boardEvidence.signedBoardHeads),
});

export const verifyBoardInclusionProof = (
    evidence: BoardEvidence,
    inclusionProof: InclusionProof,
): readonly RefusalRecord[] =>
    verifyInclusionProof(inclusionProof, evidence.headsByHash);

const collectBoardInclusionEvidence = (input: {
    readonly boardEvidence: BoardConsistencyInput;
    readonly inclusionProof: InclusionProof;
    readonly objectRefusals?: readonly RefusalRecord[];
}): BoardInclusionEvidence => {
    const evidence = collectBoardEvidence(input.boardEvidence);

    return {
        ...evidence,
        refusedObjects: [
            ...evidence.boardResult.refusedObjects,
            ...(input.objectRefusals ?? []),
            ...verifyBoardInclusionProof(evidence, input.inclusionProof),
        ],
    };
};

export const collectSignedBoardInclusionEvidence = (input: {
    readonly acceptedObjectHash: ProtocolHash;
    readonly boardEvidence: BoardConsistencyInput;
    readonly extraAcceptedHashes?: readonly ProtocolHash[];
    readonly inclusionProof: InclusionProof;
    readonly objectRefusals: readonly RefusalRecord[];
    readonly signature: ProtocolSignatureEnvelope;
    readonly signatureExpectation: SignatureExpectation;
}): BoardInclusionEvidence => {
    const evidence = collectBoardInclusionEvidence(input);
    const refusedObjects = [...evidence.refusedObjects];
    const signatureResult = verifySignedObjectSignature(
        input.signature,
        input.signatureExpectation,
    );

    refusedObjects.push(...signatureResult.refusedObjects);

    return {
        ...evidence,
        refusedObjects,
    };
};

export const buildSignedBoardShellVerificationBase = (
    evidence: BoardInclusionEvidence,
): SignedBoardShellVerificationBase => ({
    isValid: evidence.refusedObjects.length === 0,
    refusedObjects: evidence.refusedObjects,
    forkEvidence: evidence.boardResult.forkEvidence,
});
