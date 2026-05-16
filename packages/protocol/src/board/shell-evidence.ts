import {
    verifySignedObjectSignature,
    type SignatureExpectation,
} from '@sealed-lattice/crypto';
import type {
    BoardConsistencyInput,
    BoardConsistencyVerification,
    InclusionProof,
    ProtocolDigest,
    ProtocolSignatureEnvelope,
    RefusalRecord,
    SignedBoardHead,
} from '@sealed-lattice/types';

import {
    buildBoardHeadMap,
    uniqueStrings,
} from '../common/verification-helpers.js';

import { verifyBoardConsistency, verifyInclusionProof } from './index.js';

type BoardInclusionEvidence = {
    readonly boardResult: BoardConsistencyVerification;
    readonly headsByDigest: ReadonlyMap<ProtocolDigest, SignedBoardHead>;
    readonly refusedObjects: RefusalRecord[];
};

type SignedBoardShellVerificationBase = {
    readonly ok: boolean;
    readonly statusLabels: BoardConsistencyVerification['statusLabels'];
    readonly acceptedDigests: readonly ProtocolDigest[];
    readonly refusedObjects: readonly RefusalRecord[];
    readonly forkEvidence: BoardConsistencyVerification['forkEvidence'];
};

const collectBoardInclusionEvidence = (input: {
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

export const collectSignedBoardInclusionEvidence = (input: {
    readonly acceptedObjectDigest: ProtocolDigest;
    readonly boardEvidence: BoardConsistencyInput;
    readonly extraAcceptedDigests?: readonly ProtocolDigest[];
    readonly inclusionProof: InclusionProof;
    readonly objectRefusals: readonly RefusalRecord[];
    readonly signature: ProtocolSignatureEnvelope;
    readonly signatureExpectation: SignatureExpectation;
}): BoardInclusionEvidence & {
    readonly acceptedDigests: readonly ProtocolDigest[];
} => {
    const evidence = collectBoardInclusionEvidence(input);
    const refusedObjects = [...evidence.refusedObjects];
    const signatureResult = verifySignedObjectSignature(
        input.signature,
        input.signatureExpectation,
    );

    refusedObjects.push(...signatureResult.refusedObjects);

    return {
        ...evidence,
        acceptedDigests:
            refusedObjects.length === 0
                ? uniqueStrings([
                      ...evidence.boardResult.acceptedDigests,
                      input.acceptedObjectDigest,
                      input.inclusionProof.inclusionProofDigest,
                      ...(input.extraAcceptedDigests ?? []),
                  ])
                : [],
        refusedObjects,
    };
};

export const buildSignedBoardShellVerificationBase = (
    evidence: BoardInclusionEvidence & {
        readonly acceptedDigests: readonly ProtocolDigest[];
    },
): SignedBoardShellVerificationBase => ({
    ok: evidence.refusedObjects.length === 0,
    statusLabels: evidence.boardResult.statusLabels,
    acceptedDigests:
        evidence.refusedObjects.length === 0 ? evidence.acceptedDigests : [],
    refusedObjects: evidence.refusedObjects,
    forkEvidence: evidence.boardResult.forkEvidence,
});
