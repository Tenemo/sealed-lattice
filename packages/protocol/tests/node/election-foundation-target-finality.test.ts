import { describe, expect, it } from 'vitest';

import {
    type TargetFinalityRecord,
    createBoardEvidence,
    createBoardHead,
    createInclusionProof,
    createTargetFinalityRecord,
    createTargetProposalHead,
    createWitnessCheckpoint,
    deriveProtocolDigest,
    deriveTargetFinalityRecordDigest,
    deriveWitnessPolicyDigest,
    targetFinalityPolicy,
    verifyTargetFinality,
    witnessIdentities,
    witnessPolicy,
    witnessPublicKeyDigests,
} from './election-foundation-test-helpers';

describe('target finality', () => {
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
