import {
    targetDecryptionProfileId,
    type EvaluatorReplayRecord,
    type SignedBoardHead,
    type TargetAcceptedRecord,
    type TargetFinalityRecord,
    type TopKDecryptionShareShell,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    createBoardEvidence,
    createBoardHead,
    createBoardHeadWithObjects,
    createTargetFinalityRecord,
} from './election-foundation-board-helpers';
import {
    ceremonyId,
    createKeyFixture,
    createSignature,
    defaultEvaluatorReplayRecordHash,
    deriveFixtureHash,
    manifestOpaqueBindings,
    organizerPublicKeyHash,
    targetFinalityPolicy,
    witnessPolicy,
    witnessPublicKeyHashes,
} from './election-foundation-fixture-constants';

import { verifyTargetFinality } from '#packages/protocol/src/finality/index';
import {
    deriveTargetAcceptedRecordHash,
    deriveTopKDecryptionShareHash,
    verifyTargetAcceptedRecord,
    verifyTopKDecryptionShareShell,
} from '#packages/protocol/src/target-decryption/index';

const trusteeIdentity = 'trustee-1';
const trusteePublicKeyHash = createKeyFixture(
    `trustee:${trusteeIdentity}`,
).publicKeyHash;

const createFinalityFixture = (): {
    readonly genesisHead: SignedBoardHead;
    readonly finalizedHead: SignedBoardHead;
    readonly targetFinalityRecord: TargetFinalityRecord;
} => {
    const genesisHead = createBoardHead(0, null);
    const finalizedHead = createBoardHeadWithObjects(1, genesisHead.headHash, [
        {
            boardPosition: 0,
            objectHash: defaultEvaluatorReplayRecordHash,
            objectType: 'EvaluatorReplayRecord',
        },
    ]).head;
    const targetFinalityRecord = createTargetFinalityRecord(finalizedHead);

    return { genesisHead, finalizedHead, targetFinalityRecord };
};

const createEvaluatorReplayRecord = (
    targetFinalityRecord: TargetFinalityRecord,
): EvaluatorReplayRecord => {
    const checkpoint = targetFinalityRecord.targetFinalityCheckpoint;

    return {
        objectType: 'EvaluatorReplayRecord',
        objectVersion: 1,
        evaluatorReplayRecordHash: checkpoint.evaluatorReplayRecordHash,
        ceremonyId,
        electionManifestHash: checkpoint.electionManifestHash,
        targetProposalHash: targetFinalityRecord.targetProposalHash,
        encryptedBallotAggregateHash: checkpoint.encryptedBallotAggregateHash,
        targetFinalityRecordHash: targetFinalityRecord.targetFinalityRecordHash,
        evaluatorReplayProfileHash: checkpoint.evaluatorReplayProfileHash,
        evaluatorReplayContextHash: checkpoint.evaluatorReplayContextHash,
        targetCiphertextHash: checkpoint.targetCiphertextHash,
        targetLayoutHash: checkpoint.targetLayoutHash,
        replayEvidenceRoot: deriveFixtureHash(
            'fixture-evaluator-replay-evidence-v1',
            { targetProposalHash: targetFinalityRecord.targetProposalHash },
        ),
        mobileProfileHash: manifestOpaqueBindings.mobileProfileHash,
        recoveryEpoch: 0,
        deviceEpoch: 0,
        signature: createSignature(
            'EvaluatorReplayRecord',
            'Organizer',
            'organizer',
            organizerPublicKeyHash,
            checkpoint.evaluatorReplayRecordHash,
            {
                manifestHash: checkpoint.electionManifestHash,
            },
        ),
    };
};

const createAcceptedTargetFixture = (): {
    readonly genesisHead: SignedBoardHead;
    readonly finalizedHead: SignedBoardHead;
    readonly acceptedHead: SignedBoardHead;
    readonly targetFinalityRecord: TargetFinalityRecord;
    readonly evaluatorReplayRecord: EvaluatorReplayRecord;
    readonly targetAcceptedRecord: TargetAcceptedRecord;
} => {
    const { genesisHead, finalizedHead, targetFinalityRecord } =
        createFinalityFixture();
    const evaluatorReplayRecord =
        createEvaluatorReplayRecord(targetFinalityRecord);
    const checkpoint = targetFinalityRecord.targetFinalityCheckpoint;
    const acceptedPayload = {
        objectType: 'TargetAcceptedRecord',
        objectVersion: 1,
        ceremonyId,
        electionManifestHash: checkpoint.electionManifestHash,
        targetFinalityScope: targetFinalityRecord.targetFinalityScope,
        targetProposalHash: targetFinalityRecord.targetProposalHash,
        evaluatorReplayRecordHash: checkpoint.evaluatorReplayRecordHash,
        targetContextHash: deriveFixtureHash('fixture-target-context-v1', {
            targetProposalHash: targetFinalityRecord.targetProposalHash,
        }),
        targetFinalityRecordHash: targetFinalityRecord.targetFinalityRecordHash,
        targetFinalityCheckpointHash: checkpoint.targetFinalityCheckpointHash,
        evaluatorReplayProfileHash: checkpoint.evaluatorReplayProfileHash,
        targetPreimageHash: deriveFixtureHash('fixture-target-preimage-v1', {
            targetCiphertextHash: checkpoint.targetCiphertextHash,
        }),
        targetCiphertextHash: checkpoint.targetCiphertextHash,
        targetLayoutHash: checkpoint.targetLayoutHash,
        targetDecryptionProfileHash:
            manifestOpaqueBindings.targetDecryptionProfileHash,
        targetDecryptionProfileId,
        targetBasisHash: manifestOpaqueBindings.targetBasisHash,
        acceptanceMode: 'evaluator-replay',
        boardSequence: 2,
        boardPosition: 0,
        organizerIdentity: 'organizer',
    } satisfies Omit<
        TargetAcceptedRecord,
        'targetAcceptedRecordHash' | 'signature'
    >;
    const targetAcceptedRecordHash =
        deriveTargetAcceptedRecordHash(acceptedPayload);
    const acceptedHead = createBoardHeadWithObjects(
        acceptedPayload.boardSequence,
        finalizedHead.headHash,
        [
            {
                boardPosition: acceptedPayload.boardPosition,
                objectHash: targetAcceptedRecordHash,
                objectType: 'TargetAcceptedRecord',
            },
        ],
    ).head;
    const targetAcceptedRecord = {
        ...acceptedPayload,
        targetAcceptedRecordHash,
        signature: createSignature(
            'TargetAcceptedRecord',
            'Organizer',
            acceptedPayload.organizerIdentity,
            organizerPublicKeyHash,
            targetAcceptedRecordHash,
            {
                boardHeadHash: acceptedHead.headHash,
                manifestHash: acceptedPayload.electionManifestHash,
            },
        ),
    };

    return {
        genesisHead,
        finalizedHead,
        acceptedHead,
        targetFinalityRecord,
        evaluatorReplayRecord,
        targetAcceptedRecord,
    };
};

const createShare = (
    targetAcceptedRecord: TargetAcceptedRecord,
    shareHead: SignedBoardHead,
    overrides: Partial<
        Omit<TopKDecryptionShareShell, 'topKDecryptionShareHash' | 'signature'>
    > = {},
): TopKDecryptionShareShell => {
    const sharePayload = {
        objectType: 'TopKDecryptionShare',
        objectVersion: 1,
        ceremonyId,
        electionManifestHash: targetAcceptedRecord.electionManifestHash,
        trusteeIdentity,
        targetAcceptedRecordHash: targetAcceptedRecord.targetAcceptedRecordHash,
        targetProposalHash: targetAcceptedRecord.targetProposalHash,
        targetPreimageHash: targetAcceptedRecord.targetPreimageHash,
        targetFinalityRecordHash: targetAcceptedRecord.targetFinalityRecordHash,
        targetFinalityCheckpointHash:
            targetAcceptedRecord.targetFinalityCheckpointHash,
        evaluatorReplayRecordHash:
            targetAcceptedRecord.evaluatorReplayRecordHash,
        targetContextHash: targetAcceptedRecord.targetContextHash,
        targetCiphertextHash: targetAcceptedRecord.targetCiphertextHash,
        targetDecryptionProfileHash:
            targetAcceptedRecord.targetDecryptionProfileHash,
        targetDecryptionPreparationRecordHash: deriveFixtureHash(
            'fixture-target-decryption-preparation-v1',
            {
                targetAcceptedRecordHash:
                    targetAcceptedRecord.targetAcceptedRecordHash,
            },
        ),
        targetDecryptionCiphertextHash:
            targetAcceptedRecord.targetCiphertextHash,
        targetBasisHash: targetAcceptedRecord.targetBasisHash,
        thresholdShareVerificationKeyRoot:
            manifestOpaqueBindings.thresholdShareVerificationKeyRoot,
        thresholdShareVerificationKeyHash:
            manifestOpaqueBindings.thresholdShareVerificationKeyHash,
        trusteeThresholdVerificationKeyHash:
            manifestOpaqueBindings.trusteeThresholdVerificationKeyHash,
        boardSequence: shareHead.boardSequence,
        boardPosition: 0,
        recoveryEpoch: 0,
        deviceEpoch: 0,
        shareRoot: deriveFixtureHash('fixture-target-decryption-share-v1', {
            targetAcceptedRecordHash:
                targetAcceptedRecord.targetAcceptedRecordHash,
            trusteeIdentity,
        }),
        ...overrides,
    } satisfies Omit<
        TopKDecryptionShareShell,
        'topKDecryptionShareHash' | 'signature'
    >;
    const topKDecryptionShareHash = deriveTopKDecryptionShareHash(sharePayload);

    return {
        ...sharePayload,
        topKDecryptionShareHash,
        signature: createSignature(
            'TopKDecryptionShare',
            'Trustee',
            sharePayload.trusteeIdentity,
            trusteePublicKeyHash,
            topKDecryptionShareHash,
            {
                boardHeadHash: shareHead.headHash,
                manifestHash: sharePayload.electionManifestHash,
            },
        ),
    };
};

describe('target-bound decryption shell verification', () => {
    it('accepts a share shell only when it is bound to the accepted target ciphertext', () => {
        const fixture = createAcceptedTargetFixture();
        const finalityVerification = verifyTargetFinality({
            boardEvidence: createBoardEvidence([
                fixture.genesisHead,
                fixture.finalizedHead,
            ]),
            record: fixture.targetFinalityRecord,
            targetFinalityPolicy,
            witnessPolicy,
            witnessPublicKeyHashes,
        });
        const targetAcceptedRecordInclusionProof = createBoardHeadWithObjects(
            fixture.acceptedHead.boardSequence,
            fixture.finalizedHead.headHash,
            [
                {
                    boardPosition: fixture.targetAcceptedRecord.boardPosition,
                    objectHash:
                        fixture.targetAcceptedRecord.targetAcceptedRecordHash,
                    objectType: 'TargetAcceptedRecord',
                },
            ],
        ).inclusionProofs[0];
        if (targetAcceptedRecordInclusionProof === undefined) {
            throw new Error('Target accepted inclusion proof was not created.');
        }
        const acceptedVerification = verifyTargetAcceptedRecord({
            boardEvidence: createBoardEvidence([
                fixture.genesisHead,
                fixture.finalizedHead,
                fixture.acceptedHead,
            ]),
            targetAcceptedRecord: fixture.targetAcceptedRecord,
            targetAcceptedRecordInclusionProof,
            targetFinalityRecord: fixture.targetFinalityRecord,
            targetFinalityVerification: finalityVerification,
            evaluatorReplayRecord: fixture.evaluatorReplayRecord,
            expectedOrganizerPublicKeyHash: organizerPublicKeyHash,
        });
        const unsignedShareHead = createBoardHead(
            3,
            fixture.acceptedHead.headHash,
        );
        const share = createShare(
            fixture.targetAcceptedRecord,
            unsignedShareHead,
        );
        const shareHead = createBoardHeadWithObjects(
            3,
            fixture.acceptedHead.headHash,
            [
                {
                    boardPosition: share.boardPosition,
                    objectHash: share.topKDecryptionShareHash,
                    objectType: 'TopKDecryptionShare',
                },
            ],
        ).head;
        const signedShare = createShare(
            fixture.targetAcceptedRecord,
            shareHead,
        );
        const shareInclusionProof = createBoardHeadWithObjects(
            shareHead.boardSequence,
            fixture.acceptedHead.headHash,
            [
                {
                    boardPosition: signedShare.boardPosition,
                    objectHash: signedShare.topKDecryptionShareHash,
                    objectType: 'TopKDecryptionShare',
                },
            ],
        ).inclusionProofs[0];
        if (shareInclusionProof === undefined) {
            throw new Error(
                'Decryption share inclusion proof was not created.',
            );
        }

        expect(finalityVerification.ok).toBe(true);
        expect(acceptedVerification.ok).toBe(true);
        const shareVerification = verifyTopKDecryptionShareShell({
            boardEvidence: createBoardEvidence([
                fixture.genesisHead,
                fixture.finalizedHead,
                fixture.acceptedHead,
                shareHead,
            ]),
            decryptionShare: signedShare,
            decryptionShareInclusionProof: shareInclusionProof,
            targetAcceptedRecord: fixture.targetAcceptedRecord,
            targetAcceptedRecordVerification: acceptedVerification,
            expectedTrusteePublicKeyHash: trusteePublicKeyHash,
        });

        expect(shareVerification).toMatchObject({
            ok: true,
            topKDecryptionShareHash: signedShare.topKDecryptionShareHash,
            targetAcceptedRecordHash:
                fixture.targetAcceptedRecord.targetAcceptedRecordHash,
            targetFinalityRecordHash:
                fixture.targetFinalityRecord.targetFinalityRecordHash,
        });
    });

    it('refuses a share shell for any ciphertext other than the accepted target', () => {
        const fixture = createAcceptedTargetFixture();
        const finalityVerification = verifyTargetFinality({
            boardEvidence: createBoardEvidence([
                fixture.genesisHead,
                fixture.finalizedHead,
            ]),
            record: fixture.targetFinalityRecord,
            targetFinalityPolicy,
            witnessPolicy,
            witnessPublicKeyHashes,
        });
        const targetAcceptedRecordInclusionProof = createBoardHeadWithObjects(
            fixture.acceptedHead.boardSequence,
            fixture.finalizedHead.headHash,
            [
                {
                    boardPosition: fixture.targetAcceptedRecord.boardPosition,
                    objectHash:
                        fixture.targetAcceptedRecord.targetAcceptedRecordHash,
                    objectType: 'TargetAcceptedRecord',
                },
            ],
        ).inclusionProofs[0];
        if (targetAcceptedRecordInclusionProof === undefined) {
            throw new Error('Target accepted inclusion proof was not created.');
        }
        const acceptedVerification = verifyTargetAcceptedRecord({
            boardEvidence: createBoardEvidence([
                fixture.genesisHead,
                fixture.finalizedHead,
                fixture.acceptedHead,
            ]),
            targetAcceptedRecord: fixture.targetAcceptedRecord,
            targetAcceptedRecordInclusionProof,
            targetFinalityRecord: fixture.targetFinalityRecord,
            targetFinalityVerification: finalityVerification,
            evaluatorReplayRecord: fixture.evaluatorReplayRecord,
            expectedOrganizerPublicKeyHash: organizerPublicKeyHash,
        });
        const shareHead = createBoardHead(3, fixture.acceptedHead.headHash);
        const wrongCiphertextHash = deriveFixtureHash(
            'fixture-non-target-ciphertext-v1',
            { target: 'aggregate-score-or-intermediate' },
        );
        const share = createShare(fixture.targetAcceptedRecord, shareHead, {
            targetDecryptionCiphertextHash: wrongCiphertextHash,
        });
        const includedShareHead = createBoardHeadWithObjects(
            shareHead.boardSequence,
            fixture.acceptedHead.headHash,
            [
                {
                    boardPosition: share.boardPosition,
                    objectHash: share.topKDecryptionShareHash,
                    objectType: 'TopKDecryptionShare',
                },
            ],
        ).head;
        const signedShare = createShare(
            fixture.targetAcceptedRecord,
            includedShareHead,
            {
                targetDecryptionCiphertextHash: wrongCiphertextHash,
            },
        );
        const shareInclusionProof = createBoardHeadWithObjects(
            includedShareHead.boardSequence,
            fixture.acceptedHead.headHash,
            [
                {
                    boardPosition: signedShare.boardPosition,
                    objectHash: signedShare.topKDecryptionShareHash,
                    objectType: 'TopKDecryptionShare',
                },
            ],
        ).inclusionProofs[0];
        if (shareInclusionProof === undefined) {
            throw new Error(
                'Decryption share inclusion proof was not created.',
            );
        }

        const shareVerification = verifyTopKDecryptionShareShell({
            boardEvidence: createBoardEvidence([
                fixture.genesisHead,
                fixture.finalizedHead,
                fixture.acceptedHead,
                includedShareHead,
            ]),
            decryptionShare: signedShare,
            decryptionShareInclusionProof: shareInclusionProof,
            targetAcceptedRecord: fixture.targetAcceptedRecord,
            targetAcceptedRecordVerification: acceptedVerification,
            expectedTrusteePublicKeyHash: trusteePublicKeyHash,
        });

        expect(shareVerification.ok).toBe(false);
        expect(
            shareVerification.refusedObjects.some(
                (refusal) =>
                    refusal.code === 'DecryptionShareInvalid' &&
                    refusal.message.includes(
                        'Only the accepted target ciphertext',
                    ),
            ),
        ).toBe(true);
    });
});
