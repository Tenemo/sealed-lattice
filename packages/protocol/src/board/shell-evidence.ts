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

import {
    buildBoardHeadMap,
    uniqueStrings,
} from '../common/verification-helpers.js';

import { verifyBoardConsistency, verifyInclusionProof } from './index.js';

type BoardInclusionEvidence = {
    readonly boardResult: BoardConsistencyVerification;
    readonly headsByHash: ReadonlyMap<ProtocolHash, SignedBoardHead>;
    readonly refusedObjects: RefusalRecord[];
};

type SignedBoardShellVerificationBase = {
    readonly ok: boolean;
    readonly statusLabels: BoardConsistencyVerification['statusLabels'];
    readonly acceptedHashes: readonly ProtocolHash[];
    readonly refusedObjects: readonly RefusalRecord[];
    readonly forkEvidence: BoardConsistencyVerification['forkEvidence'];
};

const collectBoardInclusionEvidence = (input: {
    readonly boardEvidence: BoardConsistencyInput;
    readonly inclusionProof: InclusionProof;
    readonly objectRefusals: readonly RefusalRecord[];
}): BoardInclusionEvidence => {
    const boardResult = verifyBoardConsistency(input.boardEvidence);
    const headsByHash = buildBoardHeadMap(input.boardEvidence.signedBoardHeads);

    return {
        boardResult,
        headsByHash,
        refusedObjects: [
            ...boardResult.refusedObjects,
            ...input.objectRefusals,
            ...verifyInclusionProof(input.inclusionProof, headsByHash),
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
}): BoardInclusionEvidence & {
    readonly acceptedHashes: readonly ProtocolHash[];
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
        acceptedHashes:
            refusedObjects.length === 0
                ? uniqueStrings([
                      ...evidence.boardResult.acceptedHashes,
                      input.acceptedObjectHash,
                      input.inclusionProof.inclusionProofHash,
                      ...(input.extraAcceptedHashes ?? []),
                  ])
                : [],
        refusedObjects,
    };
};

export const buildSignedBoardShellVerificationBase = (
    evidence: BoardInclusionEvidence & {
        readonly acceptedHashes: readonly ProtocolHash[];
    },
): SignedBoardShellVerificationBase => ({
    ok: evidence.refusedObjects.length === 0,
    statusLabels: evidence.boardResult.statusLabels,
    acceptedHashes:
        evidence.refusedObjects.length === 0 ? evidence.acceptedHashes : [],
    refusedObjects: evidence.refusedObjects,
    forkEvidence: evidence.boardResult.forkEvidence,
});
