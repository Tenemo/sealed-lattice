import { describe, expect, it } from 'vitest';

import {
    type BoardConsistencyInput,
    boardPolicyHash,
    boardPublicKeyHash,
    ceremonyId,
    createBoardEvidence,
    createBoardHead,
    createBoardHeadWithObjects,
    createInclusionProof,
    createKeyFixture,
    createProtocolSignatureFixture,
    createSignature,
    deriveFixtureHash,
    deriveConflictingHeadEvidenceHash,
    deriveInclusionProofHash,
    deriveCanonicalObjectHash,
    replaceSignatureBytes,
    replaceSignaturePublicKeyBytes,
    verifyBoardConsistency,
} from './election-foundation-test-helpers';

describe('board consistency', () => {
    it('accepts an honest board chain with inclusion evidence', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createBoardHead(1, head0.headHash);
        const evaluatorReplayRecordHash = deriveFixtureHash(
            'fixture-evaluator-replay-record',
            { proposal: 'target' },
        );
        const { head: head2, inclusionProofs } = createBoardHeadWithObjects(
            2,
            head1.headHash,
            [
                {
                    objectType: 'EvaluatorReplayRecord',
                    objectHash: evaluatorReplayRecordHash,
                    boardPosition: 2,
                },
            ],
        );
        const inclusionProof = inclusionProofs[0];

        const result = verifyBoardConsistency({
            ...createBoardEvidence([head0, head1, head2]),
            inclusionProofs: [inclusionProof],
            consistencyProofs: [
                {
                    fromBoardHeadHash: head0.headHash,
                    toBoardHeadHash: head2.headHash,
                    signedBoardHeads: [head0, head1, head2],
                },
            ],
        });

        expect(result.isValid).toBe(true);
        expect(inclusionProof.boardEntryCount).toBe(3);
        expect(inclusionProof.boardEntryMerklePath).toHaveLength(1);
    });

    it('rejects board evidence without a trusted expected board key', () => {
        const head0 = createBoardHead(0, null);
        const { expectedBoardPublicKeyHash, ...untrustedBoardEvidence } =
            createBoardEvidence([head0]);

        expect(expectedBoardPublicKeyHash).toBe(boardPublicKeyHash);
        expect(
            verifyBoardConsistency(
                untrustedBoardEvidence as unknown as BoardConsistencyInput,
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongPublicKey' }),
            ]),
        );
    });

    it('rejects a board-entry Merkle path with a substituted sibling', () => {
        const head0 = createBoardHead(0, null);
        const evaluatorReplayRecordHash = deriveFixtureHash(
            'fixture-evaluator-replay-record',
            { proposal: 'target' },
        );
        const { head, inclusionProofs } = createBoardHeadWithObjects(
            1,
            head0.headHash,
            [
                {
                    objectType: 'EvaluatorReplayRecord',
                    objectHash: evaluatorReplayRecordHash,
                    boardPosition: 2,
                },
            ],
        );
        const inclusionProof = inclusionProofs[0];
        const tamperedPayload = {
            ...inclusionProof,
            boardEntryMerklePath: (
                inclusionProof.boardEntryMerklePath ?? []
            ).map((pathStep, pathStepIndex) =>
                pathStepIndex === 0
                    ? {
                          ...pathStep,
                          siblingHash: deriveCanonicalObjectHash({
                              objectType: 'BoardEntryHash',
                              pathStepIndex,
                              tampered: true,
                          }),
                      }
                    : pathStep,
            ),
        };
        const tamperedProof = {
            ...tamperedPayload,
            inclusionProofHash: deriveInclusionProofHash(tamperedPayload),
        };

        expect(
            verifyBoardConsistency({
                ...createBoardEvidence([head0, head]),
                inclusionProofs: [tamperedProof],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'InclusionProofInvalid' }),
            ]),
        );
    });

    it('rejects fabricated inclusion and non-ancestor consistency evidence', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createBoardHead(1, head0.headHash);
        const fabricatedInclusionProof = createInclusionProof(
            head1,
            'EvaluatorReplayRecord',
            deriveFixtureHash('fixture-evaluator-replay-record', {
                proposal: 'not-in-head',
            }),
        );

        expect(
            verifyBoardConsistency({
                ...createBoardEvidence([head0, head1]),
                inclusionProofs: [fabricatedInclusionProof],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'InclusionProofInvalid' }),
            ]),
        );

        expect(
            verifyBoardConsistency({
                ...createBoardEvidence([head0, head1]),
                consistencyProofs: [
                    {
                        fromBoardHeadHash: head1.headHash,
                        toBoardHeadHash: head0.headHash,
                        signedBoardHeads: [head0, head1],
                    },
                ],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardConsistencyFailure' }),
            ]),
        );
    });

    it('rejects hidden prefixes, forks, and signature substitution', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createBoardHead(1, head0.headHash);
        const nonGenesisRestart = createBoardHead(5, null);
        const skippedSequence = createBoardHead(3, head1.headHash);
        const orphan = createBoardHead(
            2,
            deriveCanonicalObjectHash({
                objectType: 'BoardHeadHash',
                hidden: true,
            }),
        );
        const fork = createBoardHead(1, head0.headHash, 'fork');
        const wrongRoleSignatureHead = {
            ...head1,
            signature: createSignature(
                'BoardHead',
                'Trustee',
                'board',
                boardPublicKeyHash,
                head1.headHash,
            ),
        };

        expect(
            verifyBoardConsistency(createBoardEvidence([head1, orphan]))
                .refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardConsistencyFailure' }),
            ]),
        );
        expect(
            verifyBoardConsistency(createBoardEvidence([nonGenesisRestart]))
                .refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardConsistencyFailure' }),
            ]),
        );
        expect(
            verifyBoardConsistency(
                createBoardEvidence([head0, head1, skippedSequence]),
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardConsistencyFailure' }),
            ]),
        );
        const forkedBoardResult = verifyBoardConsistency(
            createBoardEvidence([head0, head1, fork]),
        );

        expect(forkedBoardResult.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardForkDetected' }),
            ]),
        );
        expect(
            verifyBoardConsistency(
                createBoardEvidence([head0, wrongRoleSignatureHead]),
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongSignerRole' }),
            ]),
        );
    });

    it('rejects malformed supplied fork evidence and malformed ML-DSA signatures', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createBoardHead(1, head0.headHash);
        const compatibleEvidencePayload = {
            ceremonyId,
            boardPolicyHash,
            leftBoardHeadHash: head0.headHash,
            rightBoardHeadHash: head1.headHash,
        };
        const wrongHashForkEvidence = {
            ...compatibleEvidencePayload,
            evidenceHash: deriveCanonicalObjectHash({
                objectType: 'ChallengeDomainHash',
                payload: { wrong: true },
                purpose: 'fixture-wrong-conflicting-head-evidence',
            }),
        };
        const compatibleForkEvidence = {
            ...compatibleEvidencePayload,
            evidenceHash: deriveConflictingHeadEvidenceHash(
                compatibleEvidencePayload,
            ),
        };
        const tamperedSignatureHead = {
            ...head1,
            signature: replaceSignatureBytes(
                head1.signature,
                `${head1.signature.signatureBytesHex.startsWith('00') ? 'ff' : '00'}${head1.signature.signatureBytesHex.slice(2)}`,
            ),
        };
        const replacementKey = createKeyFixture('board:replacement-key');
        const wrongPublicKeyHead = {
            ...head1,
            signature: replaceSignaturePublicKeyBytes(
                head1.signature,
                replacementKey.publicKeyBytesHex,
            ),
        };
        const validWrongPublicKeyHead = {
            ...head1,
            signature: createProtocolSignatureFixture({
                publicKeyBytesHex: replacementKey.publicKeyBytesHex,
                publicKeyHash: replacementKey.publicKeyHash,
                secretKeyBytesHex: replacementKey.secretKeyBytesHex,
                signedRoot: head1.signature.signedRoot,
            }),
        };
        const wrongCeremonySignatureHead = {
            ...head1,
            signature: createSignature(
                'BoardHead',
                'Board',
                'board',
                boardPublicKeyHash,
                head1.headHash,
                { ceremonyId: 'ceremony-other' },
            ),
        };
        expect(
            verifyBoardConsistency({
                ...createBoardEvidence([head0, head1]),
                conflictingHeadEvidence: [wrongHashForkEvidence],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardConsistencyFailure' }),
            ]),
        );
        expect(
            verifyBoardConsistency({
                ...createBoardEvidence([head0, head1]),
                conflictingHeadEvidence: [compatibleForkEvidence],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardConsistencyFailure' }),
            ]),
        );
        expect(
            verifyBoardConsistency(
                createBoardEvidence([head0, tamperedSignatureHead]),
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'InvalidSignature' }),
            ]),
        );
        expect(
            verifyBoardConsistency(
                createBoardEvidence([head0, wrongPublicKeyHead]),
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongPublicKey' }),
            ]),
        );
        expect(
            verifyBoardConsistency(
                createBoardEvidence([head0, validWrongPublicKeyHead]),
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongPublicKey' }),
            ]),
        );
        expect(
            verifyBoardConsistency(
                createBoardEvidence([head0, wrongCeremonySignatureHead]),
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongCeremony' }),
            ]),
        );
    });
});
