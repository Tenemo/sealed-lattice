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
    boardPolicyDigest,
    boardPublicKeyDigest,
    ceremonyId,
    contextDigest,
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
    createWitnessCheckpoint,
    deriveConflictingHeadEvidenceDigest,
    deriveProtocolDigest,
    deriveTargetFinalityRecordDigest,
    deriveWitnessPolicyDigest,
    getParticipantSigningPublicKeyDigest,
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
    witnessIdentities,
    witnessPolicy,
    witnessPublicKeyDigests,
} from './election-foundation-test-helpers';

describe('board consistency and target finality', () => {
    it('accepts an honest board chain with inclusion evidence', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createBoardHead(1, head0.headDigest);
        const topKEvaluationRecordDigest = deriveProtocolDigest(
            'TopKEvaluationRecordDigest',
            {
                proposal: 'target',
            },
        );
        const { head: head2, inclusionProofs } = createBoardHeadWithObjects(
            2,
            head1.headDigest,
            [
                {
                    objectType: 'TopKEvaluationRecord',
                    objectDigest: topKEvaluationRecordDigest,
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
                    fromBoardHeadDigest: head0.headDigest,
                    toBoardHeadDigest: head2.headDigest,
                    signedBoardHeads: [head0, head1, head2],
                },
            ],
        });

        expect(result.ok).toBe(true);
        expect(result.verifiedHeadDigests).toEqual([
            head0.headDigest,
            head1.headDigest,
            head2.headDigest,
        ]);
        expect(result.acceptedDigests).toContain(
            inclusionProof.inclusionProofDigest,
        );
    });

    it('rejects board evidence without a trusted expected board key', () => {
        const head0 = createBoardHead(0, null);
        const { expectedBoardPublicKeyDigest, ...untrustedBoardEvidence } =
            createBoardEvidence([head0]);

        expect(expectedBoardPublicKeyDigest).toBe(boardPublicKeyDigest);
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

    it('rejects fabricated inclusion and non-ancestor consistency evidence', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createBoardHead(1, head0.headDigest);
        const fabricatedInclusionProof = createInclusionProof(
            head1,
            'TopKEvaluationRecord',
            deriveProtocolDigest('TopKEvaluationRecordDigest', {
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
                        proofType: 'SignedHeadChain',
                        fromBoardHeadDigest: head1.headDigest,
                        toBoardHeadDigest: head0.headDigest,
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
        const head1 = createBoardHead(1, head0.headDigest);
        const nonGenesisRestart = createBoardHead(5, null);
        const skippedSequence = createBoardHead(3, head1.headDigest);
        const orphan = createBoardHead(
            2,
            deriveProtocolDigest('BoardHeadDigest', {
                hidden: true,
            }),
        );
        const fork = createBoardHead(1, head0.headDigest, 'fork');
        const wrongRoleSignatureHead = {
            ...head1,
            signature: createSignature(
                'BoardHead',
                'Witness',
                'board',
                boardPublicKeyDigest,
                head1.headDigest,
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
        expect(
            verifyBoardConsistency(createBoardEvidence([head0, head1, fork]))
                .refusedObjects,
        ).toEqual(
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
        const head1 = createBoardHead(1, head0.headDigest);
        const compatibleEvidencePayload = {
            ceremonyId,
            boardPolicyDigest,
            leftBoardHeadDigest: head0.headDigest,
            rightBoardHeadDigest: head1.headDigest,
        };
        const wrongDigestForkEvidence = {
            ...compatibleEvidencePayload,
            evidenceDigest: deriveProtocolDigest(
                'ConflictingHeadEvidenceDigest',
                { wrong: true },
            ),
        };
        const compatibleForkEvidence = {
            ...compatibleEvidencePayload,
            evidenceDigest: deriveConflictingHeadEvidenceDigest(
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
                publicKeyDigest: replacementKey.publicKeyDigest,
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
                publicKeyDigest: boardPublicKeyDigest,
                secretKeyBytesHex: boardKeyFixture.secretKeyBytesHex,
                signedRoot: {
                    ...head1.signature.signedRoot,
                    objectRoot: head1.headDigest,
                },
            }),
        };
        const wrongCeremonySignatureHead = {
            ...head1,
            signature: createSignature(
                'BoardHead',
                'Board',
                'board',
                boardPublicKeyDigest,
                head1.headDigest,
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
                publicKeyDigest: boardPublicKeyDigest,
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
                conflictingHeadEvidence: [wrongDigestForkEvidence],
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
        const head1 = createBoardHead(1, head0.headDigest);
        const createHeadWithSignedRoot = (
            signedRoot: CanonicalSignedRootObject,
        ): SignedBoardHead => ({
            ...head1,
            signature: createProtocolSignatureFixture({
                profile,
                publicKeyBytesHex: boardKeyFixture.publicKeyBytesHex,
                publicKeyDigest: boardPublicKeyDigest,
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
            createHeadWithSignedRoot(omitSignedRootField('contextDigest')),
            createHeadWithSignedRoot({
                ...head1.signature.signedRoot,
                objectRoot: null,
                chunkMerkleRoot: null,
            }),
            createHeadWithSignedRoot({
                ...head1.signature.signedRoot,
                chunkMerkleRoot: deriveProtocolDigest('BoardRootDigest', {
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
        const targetHead = createTargetProposalHead(1, head0.headDigest);
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
        const castReceiptDigest = deriveProtocolDigest('CastReceiptDigest', {
            malformed: 'receipt',
        });
        const castReceipt = {
            objectType: 'CastReceipt',
            objectVersion: 1,
            castReceiptDigest,
            ceremonyId,
            electionManifestDigest: deriveProtocolDigest(
                'ElectionManifestDigest',
                { manifest: 'cast' },
            ),
            voterIdentity: 'participant-1',
            ballotPackageDigest: deriveProtocolDigest('BallotPackageDigest', {
                ballot: 'participant-1',
            }),
            contextDigest,
            boardSeq: head0.boardSeq,
            boardPosition: 0,
            recoveryEpoch: 0,
            deviceEpoch: 0,
            signature: createSignature(
                'CastReceipt',
                'Voter',
                'participant-1',
                getParticipantSigningPublicKeyDigest('participant-1'),
                castReceiptDigest,
            ),
        } satisfies CastReceipt;
        const malformedCastReceipt = {
            ...castReceipt,
            boardPosition: undefined,
        } as unknown as CastReceipt;
        const malformedRosterInput = createRosterManifestTranscriptInput([
            createRegistrationEntry('participant-1', 1, 0),
        ]);
        const malformedRegistration = {
            ...malformedRosterInput.registrationEntries[0],
            boardPosition: undefined,
        } as unknown as RegistrationEntry;

        const expectFailClosed = (
            verifier: () => {
                readonly ok: boolean;
                readonly refusedObjects: readonly { readonly code: string }[];
            },
            expectedCode: string,
        ): void => {
            let result:
                | {
                      readonly ok: boolean;
                      readonly refusedObjects: readonly {
                          readonly code: string;
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
        };

        delete malformedBoardHead.previousHeadDigest;
        expectFailClosed(
            () =>
                verifyBoardConsistency(
                    createBoardEvidence([
                        malformedBoardHead as SignedBoardHead,
                    ]),
                ),
            'BoardConsistencyFailure',
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
                    witnessPublicKeyDigests,
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
                        castReceiptDigest,
                    ),
                    expectedElectionManifestDigest:
                        castReceipt.electionManifestDigest,
                    expectedVoterPublicKeyDigest:
                        getParticipantSigningPublicKeyDigest('participant-1'),
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
            'RosterDigestMismatch',
        );
    });

    it('verifies 5-of-7 target finality and rejects weak witness evidence', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createTargetProposalHead(1, head0.headDigest);
        const record = createTargetFinalityRecord(head1);
        const boardEvidence = createBoardEvidence([head0, head1]);

        expect(
            verifyTargetFinality({
                boardEvidence,
                record,
                witnessPolicy,
                targetFinalityPolicy,
                witnessPublicKeyDigests,
            }),
        ).toMatchObject({
            ok: true,
            validWitnessIdentities: witnessIdentities.slice(0, 5),
        });

        const tooFewWitnesses = createTargetFinalityRecord(head1, undefined, 4);
        expect(
            verifyTargetFinality({
                boardEvidence,
                record: tooFewWitnesses,
                witnessPolicy,
                targetFinalityPolicy,
                witnessPublicKeyDigests,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WitnessQuorumNotReached' }),
            ]),
        );

        const duplicateWitnessRecord = {
            ...record,
            witnessCheckpoints: [
                record.witnessCheckpoints[0],
                record.witnessCheckpoints[0],
                ...record.witnessCheckpoints.slice(1),
            ],
        };
        const digestFixedDuplicateRecord = {
            ...duplicateWitnessRecord,
            targetFinalityRecordDigest: deriveTargetFinalityRecordDigest({
                ceremonyId: duplicateWitnessRecord.ceremonyId,
                finalizedBoardHeadDigest:
                    duplicateWitnessRecord.finalizedBoardHeadDigest,
                inclusionProof: duplicateWitnessRecord.inclusionProof,
                objectType: duplicateWitnessRecord.objectType,
                objectVersion: duplicateWitnessRecord.objectVersion,
                targetFinalityPolicyDigest:
                    duplicateWitnessRecord.targetFinalityPolicyDigest,
                targetPhase: duplicateWitnessRecord.targetPhase,
                topKEvaluationRecordDigest:
                    duplicateWitnessRecord.topKEvaluationRecordDigest,
                witnessCheckpoints: duplicateWitnessRecord.witnessCheckpoints,
                witnessPolicyDigest: duplicateWitnessRecord.witnessPolicyDigest,
            }),
        };

        expect(
            verifyTargetFinality({
                boardEvidence,
                record: digestFixedDuplicateRecord,
                witnessPolicy,
                targetFinalityPolicy,
                witnessPublicKeyDigests,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'DuplicateWitness' }),
            ]),
        );
    });

    it('rejects wrong top-k inclusion, unknown witnesses, and conflicting finalized targets', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createTargetProposalHead(1, head0.headDigest, 'left');
        const forkTopKEvaluationRecordDigest = deriveProtocolDigest(
            'TopKEvaluationRecordDigest',
            { proposal: 'fork' },
        );
        const head1Fork = createTargetProposalHead(
            1,
            head0.headDigest,
            'right',
            forkTopKEvaluationRecordDigest,
        );
        const boardEvidence = createBoardEvidence([head0, head1, head1Fork]);
        const record = createTargetFinalityRecord(head1);
        const wrongInclusionRecord = {
            ...record,
            inclusionProof: createInclusionProof(
                head1,
                'ElectionManifest',
                record.topKEvaluationRecordDigest,
            ),
        };
        const unknownWitnessRecord = {
            ...record,
            witnessCheckpoints: [
                ...record.witnessCheckpoints.slice(0, 4),
                createWitnessCheckpoint('unknown-witness', head1.headDigest),
            ],
        };
        const forkRecord = createTargetFinalityRecord(
            head1Fork,
            forkTopKEvaluationRecordDigest,
        );

        expect(
            verifyTargetFinality({
                boardEvidence: createBoardEvidence([head0, head1]),
                record: wrongInclusionRecord,
                witnessPolicy,
                targetFinalityPolicy,
                witnessPublicKeyDigests,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'TopKEvaluationRecordNotIncluded',
                }),
            ]),
        );
        expect(
            verifyTargetFinality({
                boardEvidence: createBoardEvidence([head0, head1]),
                record: unknownWitnessRecord,
                witnessPolicy,
                targetFinalityPolicy,
                witnessPublicKeyDigests,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'UnknownWitness' }),
            ]),
        );
        const forkedVerification = verifyTargetFinality({
            boardEvidence,
            record,
            witnessPolicy,
            targetFinalityPolicy,
            witnessPublicKeyDigests,
            conflictingRecords: [forkRecord],
        });

        expect(forkedVerification.ok).toBe(false);
        expect(forkedVerification.targetFinalityRecordDigest).toBeUndefined();
        expect(forkedVerification.equivocatingWitnessIdentities).toEqual(
            witnessIdentities.slice(0, 5),
        );
        expect(forkedVerification.forkEvidence).toMatchObject({
            targetPhase: 'target',
            equivocatingWitnessIdentities: witnessIdentities.slice(0, 5),
        });
        expect(forkedVerification.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardForkDetected' }),
            ]),
        );
    });

    it('rejects witness signature substitution and wrong finalized head binding', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createTargetProposalHead(1, head0.headDigest);
        const otherHead = createTargetProposalHead(
            2,
            head1.headDigest,
            'other-finalized-head',
        );
        const record = createTargetFinalityRecord(head1);
        const boardEvidence = createBoardEvidence([head0, head1, otherHead]);
        const boardSignatureAsWitnessRecord = {
            ...record,
            witnessCheckpoints: [
                {
                    ...record.witnessCheckpoints[0],
                    signature: head1.signature,
                },
                ...record.witnessCheckpoints.slice(1),
            ],
        };
        const wrongHeadWitnessRecordPayload = {
            ceremonyId: record.ceremonyId,
            finalizedBoardHeadDigest: record.finalizedBoardHeadDigest,
            inclusionProof: record.inclusionProof,
            objectType: record.objectType,
            objectVersion: record.objectVersion,
            targetFinalityPolicyDigest: record.targetFinalityPolicyDigest,
            targetPhase: record.targetPhase,
            topKEvaluationRecordDigest: record.topKEvaluationRecordDigest,
            witnessCheckpoints: [
                createWitnessCheckpoint(
                    witnessIdentities[0],
                    otherHead.headDigest,
                ),
                ...record.witnessCheckpoints.slice(1),
            ],
            witnessPolicyDigest: record.witnessPolicyDigest,
        } satisfies Omit<TargetFinalityRecord, 'targetFinalityRecordDigest'>;
        const wrongHeadWitnessRecord = {
            ...wrongHeadWitnessRecordPayload,
            targetFinalityRecordDigest: deriveTargetFinalityRecordDigest(
                wrongHeadWitnessRecordPayload,
            ),
        };

        expect(
            verifyTargetFinality({
                boardEvidence,
                record: boardSignatureAsWitnessRecord,
                witnessPolicy,
                targetFinalityPolicy,
                witnessPublicKeyDigests,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongObjectType' }),
            ]),
        );
        expect(
            verifyTargetFinality({
                boardEvidence,
                record: wrongHeadWitnessRecord,
                witnessPolicy,
                targetFinalityPolicy,
                witnessPublicKeyDigests,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'TargetFinalityPolicyMismatch',
                }),
            ]),
        );
    });

    it('rejects malformed witness policies', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createTargetProposalHead(1, head0.headDigest);
        const record = createTargetFinalityRecord(head1);

        expect(
            verifyTargetFinality({
                boardEvidence: createBoardEvidence([head0, head1]),
                record,
                witnessPolicy: {
                    ...witnessPolicy,
                    witnessIdentities: [
                        ...witnessIdentities.slice(0, 6),
                        witnessIdentities[0],
                    ],
                    witnessPolicyDigest: deriveWitnessPolicyDigest({
                        witnessIdentities: [
                            ...witnessIdentities.slice(0, 6),
                            witnessIdentities[0],
                        ],
                        witnessQuorum: 5,
                        totalWitnesses: 7,
                    }),
                },
                targetFinalityPolicy,
                witnessPublicKeyDigests,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WitnessPolicyMismatch' }),
            ]),
        );
    });
});
