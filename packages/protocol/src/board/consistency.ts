import type {
    BoardConsistencyInput,
    BoardConsistencyVerification,
    ConflictingHeadEvidence,
    RefusalRecord,
} from '@sealed-lattice/types';

import {
    buildBoardHeadMap,
    createRefusal,
    uniqueStrings,
    verificationExceptionMessage,
} from '../common/verification-helpers.js';

import {
    findConflictingHeads,
    isVerifiedAncestor,
    verifyBoardHead,
    verifyPreviousHeadLinks,
    verifySuppliedForkEvidence,
} from './head-chain.js';
import { verifyInclusionProof } from './inclusion-proof.js';

const verifyConsistencyProofs = (
    input: BoardConsistencyInput,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];

    for (const proof of input.consistencyProofs ?? []) {
        const proofHeadHashes = new Set(
            proof.signedBoardHeads.map((head) => head.headHash),
        );
        if (proof.proofType !== 'SignedHeadChain') {
            refusedObjects.push(
                createRefusal(
                    'BoardConsistencyFailure',
                    'Consistency proof must use the signed-head chain proof model.',
                    proof.toBoardHeadHash,
                    'BoardHead',
                ),
            );
        }
        if (!proofHeadHashes.has(proof.toBoardHeadHash)) {
            refusedObjects.push(
                createRefusal(
                    'BoardConsistencyFailure',
                    'Consistency proof does not contain its target board head.',
                    proof.toBoardHeadHash,
                    'BoardHead',
                ),
            );
        }
        if (
            proof.fromBoardHeadHash !== null &&
            !proofHeadHashes.has(proof.fromBoardHeadHash)
        ) {
            refusedObjects.push(
                createRefusal(
                    'BoardConsistencyFailure',
                    'Consistency proof does not contain its starting board head.',
                    proof.fromBoardHeadHash,
                    'BoardHead',
                ),
            );
        }
        const proofInput = {
            ceremonyId: input.ceremonyId,
            boardPolicyHash: input.boardPolicyHash,
            expectedBoardPublicKeyHash: input.expectedBoardPublicKeyHash,
            signedBoardHeads: proof.signedBoardHeads,
        };
        for (const head of proof.signedBoardHeads) {
            refusedObjects.push(...verifyBoardHead(proofInput, head));
        }
        refusedObjects.push(...verifyPreviousHeadLinks(proof.signedBoardHeads));

        const proofHeadsByHash = buildBoardHeadMap(proof.signedBoardHeads);
        if (
            proof.fromBoardHeadHash !== null &&
            proofHeadHashes.has(proof.fromBoardHeadHash) &&
            proofHeadHashes.has(proof.toBoardHeadHash) &&
            !isVerifiedAncestor(
                proof.fromBoardHeadHash,
                proof.toBoardHeadHash,
                proofHeadsByHash,
            )
        ) {
            refusedObjects.push(
                createRefusal(
                    'BoardConsistencyFailure',
                    'Consistency proof does not show the starting head as an ancestor of the target head.',
                    proof.toBoardHeadHash,
                    'BoardHead',
                ),
            );
        }

        const forkEvidence = findConflictingHeads(proof.signedBoardHeads);
        if (forkEvidence !== undefined) {
            refusedObjects.push(
                createRefusal(
                    'BoardForkDetected',
                    'Consistency proof contains conflicting signed heads.',
                    forkEvidence.evidenceHash,
                ),
            );
        }
    }

    return refusedObjects;
};

const verifyBoardConsistencyUnchecked = (
    input: BoardConsistencyInput,
): BoardConsistencyVerification => {
    const refusedObjects: RefusalRecord[] = [];

    if (
        typeof input.expectedBoardPublicKeyHash !== 'string' ||
        input.expectedBoardPublicKeyHash.length === 0
    ) {
        refusedObjects.push(
            createRefusal(
                'WrongPublicKey',
                'Board evidence must bind the expected board public-key hash.',
            ),
        );
    }

    if (input.signedBoardHeads.length === 0) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'Board evidence must include at least one signed board head.',
            ),
        );
    }

    for (const head of input.signedBoardHeads) {
        refusedObjects.push(...verifyBoardHead(input, head));
    }

    refusedObjects.push(...verifyPreviousHeadLinks(input.signedBoardHeads));
    refusedObjects.push(...verifyConsistencyProofs(input));

    const headsByHash = buildBoardHeadMap(input.signedBoardHeads);
    for (const inclusionProof of input.inclusionProofs ?? []) {
        refusedObjects.push(
            ...verifyInclusionProof(inclusionProof, headsByHash),
        );
    }

    const validSuppliedForkEvidence: ConflictingHeadEvidence[] = [];
    for (const evidence of input.conflictingHeadEvidence ?? []) {
        const evidenceRefusals = verifySuppliedForkEvidence(
            input,
            evidence,
            headsByHash,
        );
        refusedObjects.push(...evidenceRefusals);
        if (evidenceRefusals.length === 0) {
            validSuppliedForkEvidence.push(evidence);
        }
    }

    const suppliedForkEvidence = validSuppliedForkEvidence[0];
    const discoveredForkEvidence =
        suppliedForkEvidence ?? findConflictingHeads(input.signedBoardHeads);
    const boardAccepted =
        refusedObjects.length === 0 && discoveredForkEvidence === undefined;

    return {
        isValid:
            refusedObjects.length === 0 && discoveredForkEvidence === undefined,
        acceptedHashes: boardAccepted
            ? uniqueStrings([
                  ...input.signedBoardHeads.map((head) => head.headHash),
                  ...(input.inclusionProofs ?? []).map(
                      (proof) => proof.inclusionProofHash,
                  ),
              ])
            : [],
        refusedObjects:
            discoveredForkEvidence === undefined
                ? refusedObjects
                : [
                      ...refusedObjects,
                      createRefusal(
                          'BoardForkDetected',
                          'Supplied board evidence contains conflicting signed heads.',
                          discoveredForkEvidence.evidenceHash,
                      ),
                  ],
        forkEvidence: discoveredForkEvidence,
        verifiedHeadHashes: uniqueStrings(
            input.signedBoardHeads.map((head) => head.headHash),
        ),
    };
};

export const verifyBoardConsistency = (
    input: BoardConsistencyInput,
): BoardConsistencyVerification => {
    try {
        return verifyBoardConsistencyUnchecked(input);
    } catch (error) {
        return {
            isValid: false,
            acceptedHashes: [],
            refusedObjects: [
                createRefusal(
                    'BoardConsistencyFailure',
                    verificationExceptionMessage(
                        'Board evidence could not be canonicalized or validated.',
                        error,
                    ),
                ),
            ],
            verifiedHeadHashes: [],
        };
    }
};
