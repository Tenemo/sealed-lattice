import { describe, expect, it } from 'vitest';

import {
    type BoardConsistencyInput,
    type CanonicalSignedRootObject,
    type CastReceipt,
    type ProtocolSignatureEnvelope,
    type RegistrationEntry,
    type SignedBoardHead,
    type TargetFinalityRecord,
    boardKeyFixture,
    boardPolicyHash,
    boardPublicKeyHash,
    ceremonyId,
    contextHash,
    createBoardEvidence,
    createBoardHead,
    createBoardHeadWithObjects,
    createInclusionProof,
    createKeyFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
    createRegistrationEntry,
    createRosterManifestTranscriptInput,
    createSignature,
    createTargetFinalityRecord,
    createTargetProposalHead,
    deriveConflictingHeadEvidenceHash,
    deriveInclusionProofHash,
    deriveProtocolHash,
    getParticipantSigningPublicKeyHash,
    profile,
    replaceSignatureBytes,
    replaceSignatureProfile,
    replaceSignaturePublicKeyBytes,
    targetFinalityPolicy,
    verifyBoardConsistency,
    verifyCastReceiptShell,
    verifyRosterManifestTranscript,
    verifySignedObjectSignature,
    verifyTargetFinality,
    witnessPolicy,
    witnessPublicKeyHashes,
} from './election-foundation-test-helpers';

describe('board consistency', () => {
    it('accepts an honest board chain with inclusion evidence', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createBoardHead(1, head0.headHash);
        const topKEvaluationRecordHash = deriveProtocolHash(
            'ChallengeDomainHash',
            {
                payload: { proposal: 'target' },
                purpose: 'fixture-top-k-evaluation-record-v1',
            },
        );
        const { head: head2, inclusionProofs } = createBoardHeadWithObjects(
            2,
            head1.headHash,
            [
                {
                    objectType: 'TopKEvaluationRecord',
                    objectHash: topKEvaluationRecordHash,
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
                    proofType: 'SignedHeadChain',
                    fromBoardHeadHash: head0.headHash,
                    toBoardHeadHash: head2.headHash,
                    signedBoardHeads: [head0, head1, head2],
                },
            ],
        });

        expect(result.ok).toBe(true);
        expect(inclusionProof.boardEntryHashes).toBeUndefined();
        expect(inclusionProof.boardEntryCount).toBe(3);
        expect(inclusionProof.boardEntryMerklePath).toHaveLength(1);
        expect(result.verifiedHeadHashes).toEqual([
            head0.headHash,
            head1.headHash,
            head2.headHash,
        ]);
        expect(result.acceptedHashes).toContain(
            inclusionProof.inclusionProofHash,
        );
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
        const topKEvaluationRecordHash = deriveProtocolHash(
            'ChallengeDomainHash',
            {
                payload: { proposal: 'target' },
                purpose: 'fixture-top-k-evaluation-record-v1',
            },
        );
        const { head, inclusionProofs } = createBoardHeadWithObjects(
            1,
            head0.headHash,
            [
                {
                    objectType: 'TopKEvaluationRecord',
                    objectHash: topKEvaluationRecordHash,
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
                          siblingHash: deriveProtocolHash('BoardEntryHash', {
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
            'TopKEvaluationRecord',
            deriveProtocolHash('ChallengeDomainHash', {
                payload: { proposal: 'not-in-head' },
                purpose: 'fixture-top-k-evaluation-record-v1',
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
                        proofType: 'SignedHeadChain',
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
            deriveProtocolHash('BoardHeadHash', {
                hidden: true,
            }),
        );
        const fork = createBoardHead(1, head0.headHash, 'fork');
        const wrongRoleSignatureHead = {
            ...head1,
            signature: createSignature(
                'BoardHead',
                'Witness',
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

        expect(forkedBoardResult.acceptedHashes).toEqual([]);
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
            evidenceHash: deriveProtocolHash('ChallengeDomainHash', {
                payload: { wrong: true },
                purpose: 'fixture-wrong-conflicting-head-evidence-v1',
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
                profile,
                publicKeyBytesHex: replacementKey.publicKeyBytesHex,
                publicKeyHash: replacementKey.publicKeyHash,
                secretKeyBytesHex: replacementKey.secretKeyBytesHex,
                signedRoot: head1.signature.signedRoot,
            }),
        };
        const unsupportedModeHead = {
            ...head1,
            signature: createProtocolSignatureFixture({
                profile: createMlDsaSignatureProfileFixture({
                    mode: 'HashMLDSA',
                }),
                publicKeyBytesHex: boardKeyFixture.publicKeyBytesHex,
                publicKeyHash: boardPublicKeyHash,
                secretKeyBytesHex: boardKeyFixture.secretKeyBytesHex,
                signedRoot: {
                    ...head1.signature.signedRoot,
                    objectRoot: head1.headHash,
                },
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
        const wrongContextHead = {
            ...head1,
            signature: createProtocolSignatureFixture({
                profile: createMlDsaSignatureProfileFixture({
                    contextString: 'sealed-lattice:wrong-context',
                }),
                publicKeyBytesHex: boardKeyFixture.publicKeyBytesHex,
                publicKeyHash: boardPublicKeyHash,
                secretKeyBytesHex: boardKeyFixture.secretKeyBytesHex,
                signedRoot: head1.signature.signedRoot,
            }),
        };
        const oversizedContextHead = {
            ...head1,
            signature: replaceSignatureProfile(
                head1.signature,
                createMlDsaSignatureProfileFixture({
                    contextString: 'x'.repeat(256),
                }),
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
                createBoardEvidence([head0, unsupportedModeHead]),
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'InvalidSignature' }),
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
        expect(
            verifyBoardConsistency(
                createBoardEvidence([head0, wrongContextHead]),
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'InvalidMlDsaContext' }),
            ]),
        );
        expect(
            verifyBoardConsistency(
                createBoardEvidence([head0, oversizedContextHead]),
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'InvalidMlDsaContext' }),
            ]),
        );
    });

    it('rejects signed roots missing required envelope fields', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createBoardHead(1, head0.headHash);
        const createHeadWithSignedRoot = (
            signedRoot: CanonicalSignedRootObject,
        ): SignedBoardHead => ({
            ...head1,
            signature: createProtocolSignatureFixture({
                profile,
                publicKeyBytesHex: boardKeyFixture.publicKeyBytesHex,
                publicKeyHash: boardPublicKeyHash,
                secretKeyBytesHex: boardKeyFixture.secretKeyBytesHex,
                signedRoot,
            }),
        });
        const omitSignedRootField = (
            fieldName: keyof CanonicalSignedRootObject,
        ): CanonicalSignedRootObject => {
            const signedRoot = {
                ...head1.signature.signedRoot,
            } as Record<string, unknown>;
            delete signedRoot[fieldName];

            return signedRoot as CanonicalSignedRootObject;
        };
        const malformedHeads = [
            createHeadWithSignedRoot(omitSignedRootField('manifestHash')),
            createHeadWithSignedRoot(omitSignedRootField('boardHeadHash')),
            createHeadWithSignedRoot(omitSignedRootField('byteLength')),
            createHeadWithSignedRoot(omitSignedRootField('contextHash')),
            createHeadWithSignedRoot({
                ...head1.signature.signedRoot,
                objectRoot: null,
                chunkMerkleRoot: null,
            }),
            createHeadWithSignedRoot({
                ...head1.signature.signedRoot,
                chunkMerkleRoot: deriveProtocolHash('BoardRootHash', {
                    chunkRoot: 'ambiguous',
                }),
            }),
        ];

        for (const malformedHead of malformedHeads) {
            expect(
                verifyBoardConsistency(
                    createBoardEvidence([head0, malformedHead]),
                ).refusedObjects,
            ).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({ code: 'InvalidSignedRoot' }),
                ]),
            );
        }
    });

    it('returns structured refusals for malformed JavaScript verifier inputs', () => {
        const head0 = createBoardHead(0, null);
        const targetHead = createTargetProposalHead(1, head0.headHash);
        const targetRecord = createTargetFinalityRecord(targetHead);
        const malformedBoardHead = { ...head0 } as Record<string, unknown>;
        const malformedSignature = {
            ...head0.signature,
            signedRoot: undefined,
        } as unknown as ProtocolSignatureEnvelope;
        const malformedTargetRecord = {
            ...targetRecord,
            witnessCheckpoints: undefined,
        } as unknown as TargetFinalityRecord;
        const castReceiptHash = deriveProtocolHash('CastReceiptHash', {
            malformed: 'receipt',
        });
        const castReceipt = {
            objectType: 'CastReceipt',
            objectVersion: 1,
            castReceiptHash,
            ceremonyId,
            electionManifestHash: deriveProtocolHash('ElectionManifestHash', {
                manifest: 'cast',
            }),
            voterIdentity: 'participant-1',
            ballotPackageHash: deriveProtocolHash('BallotPackageHash', {
                ballot: 'participant-1',
            }),
            contextHash,
            boardSequence: head0.boardSequence,
            boardPosition: 0,
            recoveryEpoch: 0,
            deviceEpoch: 0,
            signature: createSignature(
                'CastReceipt',
                'Voter',
                'participant-1',
                getParticipantSigningPublicKeyHash('participant-1'),
                castReceiptHash,
            ),
        } satisfies CastReceipt;
        const malformedCastReceipt = {
            ...castReceipt,
            boardPosition: undefined,
        } as unknown as CastReceipt;
        const malformedRosterInput = createRosterManifestTranscriptInput([
            createRegistrationEntry('participant-1', 1, 0),
            createRegistrationEntry('participant-2', 1, 1),
        ]);
        const malformedRegistration = {
            ...malformedRosterInput.registrationEntries[0],
            boardPosition: undefined,
        } as unknown as RegistrationEntry;

        const expectFailClosed = (
            verifier: () => {
                readonly ok: boolean;
                readonly refusedObjects: readonly {
                    readonly code: string;
                    readonly message?: string;
                }[];
            },
            expectedCode: string,
        ): {
            readonly ok: boolean;
            readonly refusedObjects: readonly {
                readonly code: string;
                readonly message?: string;
            }[];
        } => {
            let result:
                | {
                      readonly ok: boolean;
                      readonly refusedObjects: readonly {
                          readonly code: string;
                          readonly message?: string;
                      }[];
                  }
                | undefined;

            expect(() => {
                result = verifier();
            }).not.toThrow();
            expect(result?.ok).toBe(false);
            expect(result?.refusedObjects).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({ code: expectedCode }),
                ]),
            );
            if (result === undefined) {
                throw new Error('Verifier did not return a result.');
            }

            return result;
        };

        delete malformedBoardHead.previousHeadHash;
        const malformedBoardResult = expectFailClosed(
            () =>
                verifyBoardConsistency(
                    createBoardEvidence([
                        malformedBoardHead as SignedBoardHead,
                    ]),
                ),
            'BoardConsistencyFailure',
        );
        expect(malformedBoardResult.refusedObjects[0]?.message).toContain(
            'Diagnostic:',
        );
        expectFailClosed(
            () => verifySignedObjectSignature(malformedSignature),
            'InvalidSignature',
        );
        expectFailClosed(
            () =>
                verifyTargetFinality({
                    boardEvidence: createBoardEvidence([head0, targetHead]),
                    record: malformedTargetRecord,
                    targetFinalityPolicy,
                    witnessPolicy,
                    witnessPublicKeyHashes,
                }),
            'TargetFinalityPolicyMismatch',
        );
        expectFailClosed(
            () =>
                verifyCastReceiptShell({
                    boardEvidence: createBoardEvidence([head0]),
                    receipt: malformedCastReceipt,
                    receiptInclusionProof: createInclusionProof(
                        head0,
                        'CastReceipt',
                        castReceiptHash,
                    ),
                    expectedElectionManifestHash:
                        castReceipt.electionManifestHash,
                    expectedVoterPublicKeyHash:
                        getParticipantSigningPublicKeyHash('participant-1'),
                }),
            'CastReceiptInvalid',
        );
        expectFailClosed(
            () =>
                verifyRosterManifestTranscript({
                    ...malformedRosterInput,
                    registrationEntries: [
                        malformedRegistration,
                        ...malformedRosterInput.registrationEntries.slice(1),
                    ],
                }),
            'RosterHashMismatch',
        );
    });
});
