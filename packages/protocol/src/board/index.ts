import { verifySignedObjectSignature } from '@sealed-lattice/crypto';
import type {
    BoardConsistencyInput,
    BoardConsistencyVerification,
    ConflictingHeadEvidence,
    InclusionProof,
    ProtocolHash,
    ProtocolVerificationStatusLabel,
    RefusalRecord,
    SignedBoardHead,
} from '@sealed-lattice/types';

import {
    buildBoardHeadMap,
    createRefusal,
    defaultSignedRootContextHash,
    isNonNegativeInteger,
    signedObjectRootByteLength,
    uniqueStrings,
    verificationExceptionMessage,
} from '../common/verification-helpers.js';

import {
    deriveBoardBranchNodeHash,
    deriveBoardEntryHash,
    deriveBoardEntryListRootHash,
    deriveBoardHeadHash,
    deriveBoardLeafNodeHash,
    deriveBoardRootFromNodeHash,
    deriveConflictingHeadEvidenceHash,
    deriveInclusionProofHash,
    inclusionProofUsesMerklePath,
    isBoardEntryMerklePath,
} from './hashes.js';
export {
    deriveBoardEntryHash,
    deriveBoardEntryMerklePath,
    deriveBoardHeadHash,
    deriveBoardRootHash,
    deriveConflictingHeadEvidenceHash,
    deriveInclusionProofHash,
} from './hashes.js';

const verifyBoardHead = (
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
        head.objectType !== 'BoardHead' ||
        head.objectVersion !== 1
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
    // Genesis is exactly sequence 0: only it may omit the previous-head link,
    // and conversely only it may have no previous head. The two checks are
    // mutual inverses, pinning sequence-0 <-> no-previous-head one-to-one.
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
        objectVersion: 1,
        signerRole: 'Board',
        signerIdentity: 'board',
        ceremonyId: input.ceremonyId,
        manifestHash: null,
        objectRoot: head.headHash,
        boardHeadHash: null,
        byteLength: signedObjectRootByteLength,
        recoveryEpoch: 0,
        deviceEpoch: 0,
        contextHash: defaultSignedRootContextHash,
        publicKeyHash: input.expectedBoardPublicKeyHash,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return refusedObjects;
};

// Walks the previousHeadHash chain from the descendant looking for the
// ancestor. The visited-set guards against a maliciously cyclic head chain
// causing an infinite loop; if the chain ends (or repeats) without a match,
// the ancestor relation does not hold.
const isVerifiedAncestor = (
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

const findConflictingHeads = (
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

const verifyPreviousHeadLinks = (
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

const verifySuppliedForkEvidence = (
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
        targetFinalityScope: evidence.targetFinalityScope,
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

const deriveBoardRootFromMerkleInclusionProof = (
    inclusionProof: InclusionProof,
): ProtocolHash | undefined => {
    const { boardEntryCount, boardEntryMerklePath } = inclusionProof;
    if (
        typeof boardEntryCount !== 'number' ||
        !isNonNegativeInteger(boardEntryCount) ||
        boardEntryCount === 0 ||
        !isNonNegativeInteger(inclusionProof.boardPosition) ||
        inclusionProof.boardPosition >= boardEntryCount ||
        !isBoardEntryMerklePath(boardEntryMerklePath)
    ) {
        return undefined;
    }

    // Recompute the board root from the leaf upward using parity: an
    // even-indexed node combines with its Right sibling, an odd-indexed node
    // with its Left sibling. A lone even node at the end of an odd-width level
    // (no right sibling) is carried up unchanged with no synthetic padding.
    let computedNodeHash = deriveBoardLeafNodeHash(
        inclusionProof.boardPosition,
        inclusionProof.boardEntryHash,
    );
    let levelIndex = inclusionProof.boardPosition;
    let levelWidth = boardEntryCount;
    let pathStepIndex = 0;

    while (levelWidth > 1) {
        const pathStep = boardEntryMerklePath[pathStepIndex];
        if (levelIndex % 2 === 0) {
            if (levelIndex + 1 < levelWidth) {
                if (
                    pathStep?.siblingPosition !== 'Right' ||
                    typeof pathStep.siblingHash !== 'string'
                ) {
                    return undefined;
                }
                computedNodeHash = deriveBoardBranchNodeHash(
                    computedNodeHash,
                    pathStep.siblingHash,
                );
                pathStepIndex += 1;
            }
        } else {
            if (
                pathStep?.siblingPosition !== 'Left' ||
                typeof pathStep.siblingHash !== 'string'
            ) {
                return undefined;
            }
            computedNodeHash = deriveBoardBranchNodeHash(
                pathStep.siblingHash,
                computedNodeHash,
            );
            pathStepIndex += 1;
        }

        levelIndex = Math.floor(levelIndex / 2);
        levelWidth = Math.ceil(levelWidth / 2);
    }

    // Every supplied path step must be consumed; leftover steps mean the proof
    // is malformed (more siblings than the tree height warrants).
    if (pathStepIndex !== boardEntryMerklePath.length) {
        return undefined;
    }

    return deriveBoardRootFromNodeHash(boardEntryCount, computedNodeHash);
};

export const verifyInclusionProof = (
    inclusionProof: InclusionProof,
    headsByHash: ReadonlyMap<ProtocolHash, SignedBoardHead>,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const head = headsByHash.get(inclusionProof.boardHeadHash);
    const expectedBoardEntryHash = deriveBoardEntryHash({
        boardPosition: inclusionProof.boardPosition,
        includedObjectHash: inclusionProof.includedObjectHash,
        includedObjectType: inclusionProof.includedObjectType,
    });
    const usesMerklePath = inclusionProofUsesMerklePath(inclusionProof);
    const usesBoardEntryHashList =
        inclusionProof.boardEntryHashes !== undefined;
    const expectedBoardRoot = usesMerklePath
        ? deriveBoardRootFromMerkleInclusionProof(inclusionProof)
        : Array.isArray(inclusionProof.boardEntryHashes)
          ? deriveBoardEntryListRootHash(inclusionProof.boardEntryHashes)
          : undefined;
    const expectedHash = deriveInclusionProofHash({
        boardHeadHash: inclusionProof.boardHeadHash,
        boardEntryHash: inclusionProof.boardEntryHash,
        boardEntryCount: inclusionProof.boardEntryCount,
        boardEntryMerklePath: inclusionProof.boardEntryMerklePath,
        boardEntryHashes: inclusionProof.boardEntryHashes,
        boardPosition: inclusionProof.boardPosition,
        boardRoot: inclusionProof.boardRoot,
        boardSequence: inclusionProof.boardSequence,
        includedObjectHash: inclusionProof.includedObjectHash,
        includedObjectType: inclusionProof.includedObjectType,
    });

    if (inclusionProof.inclusionProofHash !== expectedHash) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof hash does not match its canonical payload.',
                inclusionProof.inclusionProofHash,
            ),
        );
    }
    if (inclusionProof.boardEntryHash !== expectedBoardEntryHash) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof board-entry hash does not match its canonical payload.',
                inclusionProof.inclusionProofHash,
            ),
        );
    }
    if (usesMerklePath && usesBoardEntryHashList) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof must use exactly one board inclusion witness model.',
                inclusionProof.inclusionProofHash,
            ),
        );
    }
    if (!usesMerklePath && !usesBoardEntryHashList) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof must include a board inclusion witness.',
                inclusionProof.inclusionProofHash,
            ),
        );
    }
    if (expectedBoardRoot === undefined) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof board witness is malformed.',
                inclusionProof.inclusionProofHash,
            ),
        );
    } else if (inclusionProof.boardRoot !== expectedBoardRoot) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof board root does not match its board inclusion witness.',
                inclusionProof.inclusionProofHash,
            ),
        );
    }
    if (head === undefined) {
        refusedObjects.push(
            createRefusal(
                'UnknownBoardHead',
                'Inclusion proof references an unknown signed board head.',
                inclusionProof.includedObjectHash,
                inclusionProof.includedObjectType,
            ),
        );
    } else if (head.boardSequence !== inclusionProof.boardSequence) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof sequence does not match the board head.',
                inclusionProof.inclusionProofHash,
            ),
        );
    } else if (head.boardRoot !== inclusionProof.boardRoot) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof board root does not match the signed board head.',
                inclusionProof.inclusionProofHash,
            ),
        );
    }
    if (!isNonNegativeInteger(inclusionProof.boardPosition)) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof board position must be a non-negative integer.',
                inclusionProof.inclusionProofHash,
            ),
        );
    } else if (
        Array.isArray(inclusionProof.boardEntryHashes) &&
        inclusionProof.boardEntryHashes[inclusionProof.boardPosition] !==
            inclusionProof.boardEntryHash
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Inclusion proof board entry is not present at the claimed board position.',
                inclusionProof.inclusionProofHash,
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
    const statusLabels: readonly ProtocolVerificationStatusLabel[] =
        discoveredForkEvidence === undefined
            ? []
            : ['boardForkSuspected', 'boardEvidencePublished', 'forkDetected'];

    return {
        ok: refusedObjects.length === 0 && discoveredForkEvidence === undefined,
        statusLabels,
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
            ok: false,
            statusLabels: [],
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
