import type {
    BoardConsistencyInput,
    BoardConsistencyVerification,
    ConflictingHeadEvidence,
    InclusionProof,
    ProtocolDigest,
    ProtocolObjectType,
    ProtocolVerificationStatusLabel,
    RefusalRecord,
    SignedBoardHead,
} from '@sealed-lattice/types';

import { deriveProtocolDigest } from '../common/digests.js';
import { verifySignedObjectSignature } from '../common/signatures.js';
import {
    createRefusal,
    uniqueStrings,
} from '../common/verification-helpers.js';

const isNonNegativeInteger = (value: number): boolean =>
    Number.isInteger(value) && value >= 0;

type BoardEntryDigestInput = {
    readonly boardPosition: number;
    readonly includedObjectType: ProtocolObjectType;
    readonly includedObjectDigest: ProtocolDigest;
};

export const deriveBoardEntryDigest = (
    entry: BoardEntryDigestInput,
): ProtocolDigest =>
    deriveProtocolDigest('BoardEntryDigest', {
        boardPosition: entry.boardPosition,
        includedObjectDigest: entry.includedObjectDigest,
        includedObjectType: entry.includedObjectType,
    });

export const deriveBoardRootDigest = (
    boardEntryDigests: readonly ProtocolDigest[],
): ProtocolDigest =>
    deriveProtocolDigest('BoardRootDigest', { boardEntryDigests });

export const deriveBoardHeadDigest = (head: SignedBoardHead): ProtocolDigest =>
    deriveProtocolDigest('BoardHeadDigest', {
        boardPolicyDigest: head.boardPolicyDigest,
        boardRoot: head.boardRoot,
        boardSeq: head.boardSeq,
        ceremonyId: head.ceremonyId,
        objectType: head.objectType,
        objectVersion: head.objectVersion,
        previousHeadDigest: head.previousHeadDigest,
    });

export const deriveInclusionProofDigest = (
    inclusionProof: Omit<InclusionProof, 'inclusionProofDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('InclusionProofDigest', {
        boardHeadDigest: inclusionProof.boardHeadDigest,
        boardEntryDigest: inclusionProof.boardEntryDigest,
        boardEntryDigests: inclusionProof.boardEntryDigests,
        boardPosition: inclusionProof.boardPosition,
        boardRoot: inclusionProof.boardRoot,
        boardSeq: inclusionProof.boardSeq,
        includedObjectDigest: inclusionProof.includedObjectDigest,
        includedObjectType: inclusionProof.includedObjectType,
    });

export const deriveConflictingHeadEvidenceDigest = (
    evidence: Omit<ConflictingHeadEvidence, 'evidenceDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('ConflictingHeadEvidenceDigest', {
        boardPolicyDigest: evidence.boardPolicyDigest,
        ceremonyId: evidence.ceremonyId,
        equivocatingWitnessIdentities:
            evidence.equivocatingWitnessIdentities ?? [],
        leftBoardHeadDigest: evidence.leftBoardHeadDigest,
        rightBoardHeadDigest: evidence.rightBoardHeadDigest,
        targetPhase: evidence.targetPhase ?? null,
    });

const verifyBoardHead = (
    input: BoardConsistencyInput,
    head: SignedBoardHead,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedHeadDigest = deriveBoardHeadDigest(head);

    if (head.headDigest !== expectedHeadDigest) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'Board head digest does not match its canonical payload.',
                head.headDigest,
                'BoardHead',
            ),
        );
    }
    if (head.ceremonyId !== input.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Board head ceremony does not match the verified ceremony.',
                head.headDigest,
                'BoardHead',
            ),
        );
    }
    if (head.boardPolicyDigest !== input.boardPolicyDigest) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'Board head policy digest does not match the verified board policy.',
                head.headDigest,
                'BoardHead',
            ),
        );
    }
    if (
        !isNonNegativeInteger(head.boardSeq) ||
        head.objectType !== 'BoardHead' ||
        head.objectVersion !== 1
    ) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'Board head version and sequence must be canonical.',
                head.headDigest,
                'BoardHead',
            ),
        );
    }
    if (head.previousHeadDigest === null && head.boardSeq !== 0) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'Only the genesis board head may omit the previous head digest.',
                head.headDigest,
                'BoardHead',
            ),
        );
    }
    if (head.previousHeadDigest !== null && head.boardSeq === 0) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'The genesis board head must not bind a previous head digest.',
                head.headDigest,
                'BoardHead',
            ),
        );
    }

    const signatureResult = verifySignedObjectSignature(head.signature, {
        objectType: 'BoardHead',
        objectVersion: 1,
        signerRole: 'Board',
        ceremonyId: input.ceremonyId,
        manifestHash: null,
        objectRoot: head.headDigest,
        boardHeadHash: null,
        publicKeyDigest: input.expectedBoardPublicKeyDigest,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return refusedObjects;
};

const buildHeadMap = (
    heads: readonly SignedBoardHead[],
): Map<ProtocolDigest, SignedBoardHead> =>
    new Map(heads.map((head) => [head.headDigest, head]));

export const isVerifiedAncestor = (
    ancestorDigest: ProtocolDigest,
    descendantDigest: ProtocolDigest,
    headsByDigest: ReadonlyMap<ProtocolDigest, SignedBoardHead>,
): boolean => {
    let currentHead = headsByDigest.get(descendantDigest);
    const visitedHeadDigests = new Set<ProtocolDigest>();

    while (currentHead !== undefined) {
        if (currentHead.headDigest === ancestorDigest) {
            return true;
        }
        if (
            currentHead.previousHeadDigest === null ||
            visitedHeadDigests.has(currentHead.headDigest)
        ) {
            return false;
        }

        visitedHeadDigests.add(currentHead.headDigest);
        currentHead = headsByDigest.get(currentHead.previousHeadDigest);
    }

    return false;
};

const findConflictingHeads = (
    heads: readonly SignedBoardHead[],
): ConflictingHeadEvidence | undefined => {
    const headsByDigest = buildHeadMap(heads);

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
                leftHead.boardPolicyDigest !== rightHead.boardPolicyDigest
            ) {
                continue;
            }
            const leftIsAncestor = isVerifiedAncestor(
                leftHead.headDigest,
                rightHead.headDigest,
                headsByDigest,
            );
            const rightIsAncestor = isVerifiedAncestor(
                rightHead.headDigest,
                leftHead.headDigest,
                headsByDigest,
            );

            if (!leftIsAncestor && !rightIsAncestor) {
                const evidence = {
                    ceremonyId: leftHead.ceremonyId,
                    boardPolicyDigest: leftHead.boardPolicyDigest,
                    leftBoardHeadDigest: leftHead.headDigest,
                    rightBoardHeadDigest: rightHead.headDigest,
                };

                return {
                    ...evidence,
                    evidenceDigest:
                        deriveConflictingHeadEvidenceDigest(evidence),
                };
            }
        }
    }

    return undefined;
};

const verifyPreviousHeadLinks = (
    heads: readonly SignedBoardHead[],
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const headsByDigest = buildHeadMap(heads);

    for (const head of heads) {
        if (head.previousHeadDigest === null) {
            continue;
        }
        const previousHead = headsByDigest.get(head.previousHeadDigest);
        if (previousHead === undefined) {
            refusedObjects.push(
                createRefusal(
                    'BoardConsistencyFailure',
                    'Board head chain is missing a previous signed head.',
                    head.headDigest,
                    'BoardHead',
                ),
            );
            continue;
        }
        if (previousHead.boardSeq + 1 !== head.boardSeq) {
            refusedObjects.push(
                createRefusal(
                    'BoardConsistencyFailure',
                    'Board head sequence must increase by one across the signed chain.',
                    head.headDigest,
                    'BoardHead',
                ),
            );
        }
    }

    return refusedObjects;
};

const verifySuppliedForkEvidence = (
    input: BoardConsistencyInput,
    evidence: ConflictingHeadEvidence,
    headsByDigest: ReadonlyMap<ProtocolDigest, SignedBoardHead>,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveConflictingHeadEvidenceDigest({
        boardPolicyDigest: evidence.boardPolicyDigest,
        ceremonyId: evidence.ceremonyId,
        equivocatingWitnessIdentities:
            evidence.equivocatingWitnessIdentities ?? [],
        leftBoardHeadDigest: evidence.leftBoardHeadDigest,
        rightBoardHeadDigest: evidence.rightBoardHeadDigest,
        targetPhase: evidence.targetPhase,
    });

    if (evidence.evidenceDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'Supplied fork evidence digest does not match its canonical payload.',
                evidence.evidenceDigest,
            ),
        );
    }
    if (
        evidence.ceremonyId !== input.ceremonyId ||
        evidence.boardPolicyDigest !== input.boardPolicyDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'Supplied fork evidence does not match the verified ceremony and board policy.',
                evidence.evidenceDigest,
            ),
        );
    }
    const leftHead = headsByDigest.get(evidence.leftBoardHeadDigest);
    const rightHead = headsByDigest.get(evidence.rightBoardHeadDigest);
    if (leftHead === undefined || rightHead === undefined) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'Supplied fork evidence must reference known signed board heads.',
                evidence.evidenceDigest,
            ),
        );
        return refusedObjects;
    }
    if (leftHead.headDigest === rightHead.headDigest) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'Supplied fork evidence must reference two distinct board heads.',
                evidence.evidenceDigest,
            ),
        );
        return refusedObjects;
    }

    const leftIsAncestor = isVerifiedAncestor(
        leftHead.headDigest,
        rightHead.headDigest,
        headsByDigest,
    );
    const rightIsAncestor = isVerifiedAncestor(
        rightHead.headDigest,
        leftHead.headDigest,
        headsByDigest,
    );
    if (leftIsAncestor || rightIsAncestor) {
        refusedObjects.push(
            createRefusal(
                'BoardConsistencyFailure',
                'Supplied fork evidence references compatible board heads.',
                evidence.evidenceDigest,
            ),
        );
    }

    return refusedObjects;
};

export const verifyInclusionProof = (
    inclusionProof: InclusionProof,
    headsByDigest: ReadonlyMap<ProtocolDigest, SignedBoardHead>,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const head = headsByDigest.get(inclusionProof.boardHeadDigest);
    const expectedBoardEntryDigest = deriveBoardEntryDigest({
        boardPosition: inclusionProof.boardPosition,
        includedObjectDigest: inclusionProof.includedObjectDigest,
        includedObjectType: inclusionProof.includedObjectType,
    });
    const expectedBoardRoot = deriveBoardRootDigest(
        inclusionProof.boardEntryDigests,
    );
    const expectedDigest = deriveInclusionProofDigest({
        boardHeadDigest: inclusionProof.boardHeadDigest,
        boardEntryDigest: inclusionProof.boardEntryDigest,
        boardEntryDigests: inclusionProof.boardEntryDigests,
        boardPosition: inclusionProof.boardPosition,
        boardRoot: inclusionProof.boardRoot,
        boardSeq: inclusionProof.boardSeq,
        includedObjectDigest: inclusionProof.includedObjectDigest,
        includedObjectType: inclusionProof.includedObjectType,
    });

    if (inclusionProof.inclusionProofDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof digest does not match its canonical payload.',
                inclusionProof.inclusionProofDigest,
            ),
        );
    }
    if (inclusionProof.boardEntryDigest !== expectedBoardEntryDigest) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof board-entry digest does not match its canonical payload.',
                inclusionProof.inclusionProofDigest,
            ),
        );
    }
    if (inclusionProof.boardRoot !== expectedBoardRoot) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof board root does not match its board-entry digest list.',
                inclusionProof.inclusionProofDigest,
            ),
        );
    }
    if (head === undefined) {
        refusedObjects.push(
            createRefusal(
                'UnknownBoardHead',
                'Inclusion proof references an unknown signed board head.',
                inclusionProof.includedObjectDigest,
                inclusionProof.includedObjectType,
            ),
        );
    } else if (head.boardSeq !== inclusionProof.boardSeq) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof sequence does not match the board head.',
                inclusionProof.inclusionProofDigest,
            ),
        );
    } else if (head.boardRoot !== inclusionProof.boardRoot) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof board root does not match the signed board head.',
                inclusionProof.inclusionProofDigest,
            ),
        );
    }
    if (!isNonNegativeInteger(inclusionProof.boardPosition)) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof board position must be a non-negative integer.',
                inclusionProof.inclusionProofDigest,
            ),
        );
    } else if (
        inclusionProof.boardEntryDigests[inclusionProof.boardPosition] !==
        inclusionProof.boardEntryDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof board entry is not present at the claimed board position.',
                inclusionProof.inclusionProofDigest,
            ),
        );
    }

    return refusedObjects;
};

const verifyConsistencyProofs = (
    input: BoardConsistencyInput,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];

    for (const proof of input.consistencyProofs ?? []) {
        const proofHeadDigests = new Set(
            proof.signedBoardHeads.map((head) => head.headDigest),
        );
        if (proof.proofType !== 'SignedHeadChain') {
            refusedObjects.push(
                createRefusal(
                    'BoardConsistencyFailure',
                    'Consistency proof must use the signed-head chain proof model.',
                    proof.toBoardHeadDigest,
                    'BoardHead',
                ),
            );
        }
        if (!proofHeadDigests.has(proof.toBoardHeadDigest)) {
            refusedObjects.push(
                createRefusal(
                    'BoardConsistencyFailure',
                    'Consistency proof does not contain its target board head.',
                    proof.toBoardHeadDigest,
                    'BoardHead',
                ),
            );
        }
        if (
            proof.fromBoardHeadDigest !== null &&
            !proofHeadDigests.has(proof.fromBoardHeadDigest)
        ) {
            refusedObjects.push(
                createRefusal(
                    'BoardConsistencyFailure',
                    'Consistency proof does not contain its starting board head.',
                    proof.fromBoardHeadDigest,
                    'BoardHead',
                ),
            );
        }
        const proofInput = {
            ceremonyId: input.ceremonyId,
            boardPolicyDigest: input.boardPolicyDigest,
            expectedBoardPublicKeyDigest: input.expectedBoardPublicKeyDigest,
            signedBoardHeads: proof.signedBoardHeads,
        };
        for (const head of proof.signedBoardHeads) {
            refusedObjects.push(...verifyBoardHead(proofInput, head));
        }
        refusedObjects.push(...verifyPreviousHeadLinks(proof.signedBoardHeads));

        const proofHeadsByDigest = buildHeadMap(proof.signedBoardHeads);
        if (
            proof.fromBoardHeadDigest !== null &&
            proofHeadDigests.has(proof.fromBoardHeadDigest) &&
            proofHeadDigests.has(proof.toBoardHeadDigest) &&
            !isVerifiedAncestor(
                proof.fromBoardHeadDigest,
                proof.toBoardHeadDigest,
                proofHeadsByDigest,
            )
        ) {
            refusedObjects.push(
                createRefusal(
                    'BoardConsistencyFailure',
                    'Consistency proof does not show the starting head as an ancestor of the target head.',
                    proof.toBoardHeadDigest,
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
                    forkEvidence.evidenceDigest,
                ),
            );
        }
    }

    return refusedObjects;
};

export const verifyBoardConsistency = (
    input: BoardConsistencyInput,
): BoardConsistencyVerification => {
    const refusedObjects: RefusalRecord[] = [];

    if (
        typeof input.expectedBoardPublicKeyDigest !== 'string' ||
        input.expectedBoardPublicKeyDigest.length === 0
    ) {
        refusedObjects.push(
            createRefusal(
                'WrongPublicKey',
                'Board evidence must bind the expected board public-key digest.',
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

    const headsByDigest = buildHeadMap(input.signedBoardHeads);
    for (const inclusionProof of input.inclusionProofs ?? []) {
        refusedObjects.push(
            ...verifyInclusionProof(inclusionProof, headsByDigest),
        );
    }

    const validSuppliedForkEvidence: ConflictingHeadEvidence[] = [];
    for (const evidence of input.conflictingHeadEvidence ?? []) {
        const evidenceRefusals = verifySuppliedForkEvidence(
            input,
            evidence,
            headsByDigest,
        );
        refusedObjects.push(...evidenceRefusals);
        if (evidenceRefusals.length === 0) {
            validSuppliedForkEvidence.push(evidence);
        }
    }

    const suppliedForkEvidence = validSuppliedForkEvidence[0];
    const discoveredForkEvidence =
        suppliedForkEvidence ?? findConflictingHeads(input.signedBoardHeads);
    const statusLabels: readonly ProtocolVerificationStatusLabel[] =
        discoveredForkEvidence === undefined
            ? []
            : [
                  'BoardForkSuspected',
                  'BoardEvidencePublished',
                  'ForkedElection',
              ];

    return {
        ok: refusedObjects.length === 0 && discoveredForkEvidence === undefined,
        statusLabels,
        acceptedDigests: uniqueStrings([
            ...input.signedBoardHeads.map((head) => head.headDigest),
            ...(input.inclusionProofs ?? []).map(
                (proof) => proof.inclusionProofDigest,
            ),
        ]),
        refusedObjects:
            discoveredForkEvidence === undefined
                ? refusedObjects
                : [
                      ...refusedObjects,
                      createRefusal(
                          'BoardForkDetected',
                          'Supplied board evidence contains conflicting signed heads.',
                          discoveredForkEvidence.evidenceDigest,
                      ),
                  ],
        forkEvidence: discoveredForkEvidence,
        verifiedHeadDigests: uniqueStrings(
            input.signedBoardHeads.map((head) => head.headDigest),
        ),
    };
};
