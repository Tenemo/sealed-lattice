import { describe, expect, it } from 'vitest';

import {
    type TargetFinalityRecord,
    createBoardEvidence,
    createBoardHead,
    createInclusionProof,
    createTargetFinalityRecord,
    createTargetProposalHead,
    createWitnessCheckpoint,
    deriveProtocolHash,
    deriveTargetFinalityRecordHash,
    deriveWitnessPolicyHash,
    targetFinalityPolicy,
    verifyTargetFinality,
    witnessIdentities,
    witnessPolicy,
    witnessPublicKeyHashes,
} from './election-foundation-test-helpers';

describe('target finality', () => {
    it('verifies 5-of-7 target finality and rejects weak witness evidence', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createTargetProposalHead(1, head0.headHash);
        const record = createTargetFinalityRecord(head1);
        const boardEvidence = createBoardEvidence([head0, head1]);

        expect(
            verifyTargetFinality({
                boardEvidence,
                record,
                witnessPolicy,
                targetFinalityPolicy,
                witnessPublicKeyHashes,
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
                witnessPublicKeyHashes,
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
        const hashFixedDuplicateRecord = {
            ...duplicateWitnessRecord,
            targetFinalityRecordHash: deriveTargetFinalityRecordHash({
                ceremonyId: duplicateWitnessRecord.ceremonyId,
                inclusionProof: duplicateWitnessRecord.inclusionProof,
                objectType: duplicateWitnessRecord.objectType,
                objectVersion: duplicateWitnessRecord.objectVersion,
                targetFinalityCheckpoint:
                    duplicateWitnessRecord.targetFinalityCheckpoint,
                targetFinalityPolicyHash:
                    duplicateWitnessRecord.targetFinalityPolicyHash,
                targetFinalityScope: duplicateWitnessRecord.targetFinalityScope,
                targetProposalHash: duplicateWitnessRecord.targetProposalHash,
                witnessCheckpoints: duplicateWitnessRecord.witnessCheckpoints,
                witnessPolicyHash: duplicateWitnessRecord.witnessPolicyHash,
            }),
        };

        expect(
            verifyTargetFinality({
                boardEvidence,
                record: hashFixedDuplicateRecord,
                witnessPolicy,
                targetFinalityPolicy,
                witnessPublicKeyHashes,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'DuplicateWitness' }),
            ]),
        );
    });

    it('rejects wrong top-k inclusion, unknown witnesses, and conflicting finalized targets', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createTargetProposalHead(1, head0.headHash, 'left');
        const forkTopKEvaluationRecordHash = deriveProtocolHash(
            'TopKEvaluationRecordHash',
            { proposal: 'fork' },
        );
        const head1Fork = createTargetProposalHead(
            1,
            head0.headHash,
            'right',
            forkTopKEvaluationRecordHash,
        );
        const boardEvidence = createBoardEvidence([head0, head1, head1Fork]);
        const record = createTargetFinalityRecord(head1);
        const wrongInclusionRecord = {
            ...record,
            inclusionProof: createInclusionProof(
                head1,
                'ElectionManifest',
                record.targetFinalityCheckpoint.topKEvaluationRecordHash,
            ),
        };
        const unknownWitnessRecord = {
            ...record,
            witnessCheckpoints: [
                ...record.witnessCheckpoints.slice(0, 4),
                createWitnessCheckpoint('unknown-witness', head1.headHash),
            ],
        };
        const forkRecord = createTargetFinalityRecord(
            head1Fork,
            forkTopKEvaluationRecordHash,
        );

        expect(
            verifyTargetFinality({
                boardEvidence: createBoardEvidence([head0, head1]),
                record: wrongInclusionRecord,
                witnessPolicy,
                targetFinalityPolicy,
                witnessPublicKeyHashes,
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
                witnessPublicKeyHashes,
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
            witnessPublicKeyHashes,
            conflictingRecords: [forkRecord],
        });

        expect(forkedVerification.ok).toBe(false);
        expect(forkedVerification.acceptedHashes).toEqual([]);
        expect(forkedVerification.targetFinalityRecordHash).toBeUndefined();
        expect(forkedVerification.equivocatingWitnessIdentities).toEqual(
            witnessIdentities.slice(0, 5),
        );
        expect(forkedVerification.forkEvidence).toMatchObject({
            targetFinalityScope: 'target',
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
        const head1 = createTargetProposalHead(1, head0.headHash);
        const otherHead = createTargetProposalHead(
            2,
            head1.headHash,
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
            inclusionProof: record.inclusionProof,
            objectType: record.objectType,
            objectVersion: record.objectVersion,
            targetFinalityCheckpoint: record.targetFinalityCheckpoint,
            targetFinalityPolicyHash: record.targetFinalityPolicyHash,
            targetFinalityScope: record.targetFinalityScope,
            targetProposalHash: record.targetProposalHash,
            witnessCheckpoints: [
                createWitnessCheckpoint(
                    witnessIdentities[0],
                    otherHead.headHash,
                ),
                ...record.witnessCheckpoints.slice(1),
            ],
            witnessPolicyHash: record.witnessPolicyHash,
        } satisfies Omit<TargetFinalityRecord, 'targetFinalityRecordHash'>;
        const wrongHeadWitnessRecord = {
            ...wrongHeadWitnessRecordPayload,
            targetFinalityRecordHash: deriveTargetFinalityRecordHash(
                wrongHeadWitnessRecordPayload,
            ),
        };

        expect(
            verifyTargetFinality({
                boardEvidence,
                record: boardSignatureAsWitnessRecord,
                witnessPolicy,
                targetFinalityPolicy,
                witnessPublicKeyHashes,
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
                witnessPublicKeyHashes,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'TargetFinalityPolicyMismatch',
                }),
            ]),
        );
    });

    it('rejects conflicting accepted targets even on one linear board chain', () => {
        const head0 = createBoardHead(0, null);
        const firstTargetHead = createTargetProposalHead(
            1,
            head0.headHash,
            'first-target',
        );
        const secondTopKEvaluationRecordHash = deriveProtocolHash(
            'TopKEvaluationRecordHash',
            { proposal: 'second-linear-target' },
        );
        const secondTargetHead = createTargetProposalHead(
            2,
            firstTargetHead.headHash,
            'second-target',
            secondTopKEvaluationRecordHash,
        );
        const firstRecord = createTargetFinalityRecord(firstTargetHead);
        const secondRecord = createTargetFinalityRecord(
            secondTargetHead,
            secondTopKEvaluationRecordHash,
        );
        const verification = verifyTargetFinality({
            boardEvidence: createBoardEvidence([
                head0,
                firstTargetHead,
                secondTargetHead,
            ]),
            record: firstRecord,
            witnessPolicy,
            targetFinalityPolicy,
            witnessPublicKeyHashes,
            conflictingRecords: [secondRecord],
        });

        expect(verification.ok).toBe(false);
        expect(verification.acceptedHashes).toEqual([]);
        expect(verification.targetFinalityRecordHash).toBeUndefined();
        expect(verification.statusLabels).toEqual(
            expect.arrayContaining(['witnessEquivocationEvidence']),
        );
        expect(verification.equivocatingWitnessIdentities).toEqual(
            witnessIdentities.slice(0, 5),
        );
        expect(verification.forkEvidence).toMatchObject({
            leftBoardHeadHash: firstTargetHead.headHash,
            rightBoardHeadHash: secondTargetHead.headHash,
            targetFinalityScope: 'target',
            equivocatingWitnessIdentities: witnessIdentities.slice(0, 5),
        });
        expect(verification.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardForkDetected' }),
            ]),
        );
    });

    it('rejects malformed witness policies', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createTargetProposalHead(1, head0.headHash);
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
                    witnessPolicyHash: deriveWitnessPolicyHash({
                        witnessIdentities: [
                            ...witnessIdentities.slice(0, 6),
                            witnessIdentities[0],
                        ],
                        witnessQuorum: 5,
                        totalWitnesses: 7,
                    }),
                },
                targetFinalityPolicy,
                witnessPublicKeyHashes,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WitnessPolicyMismatch' }),
            ]),
        );
    });
});
