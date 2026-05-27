import {
    encryptedAggregateBridgeProfileId,
    type AggregateContribution,
    type AggregateReadyRecord,
    type ProtocolDigest,
    type ProtocolSignatureEnvelope,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    deriveAggregateReadyRecordDigest,
    deriveEncryptedAggregateReconstructionRoot,
} from '../../src/ballot-privacy/aggregate-bridge/digests.js';
import {
    createPendingBridgeProofRecordFromBridgeEvidence,
    type PendingBridgeProofRecordFromEvidenceInput,
} from '../../src/ballot-privacy/aggregate-bridge/structure-verification.js';
import { forbiddenPublicWitnessFieldNames } from '../../src/ballot-privacy/aggregate-derivation/constants.js';
import {
    createAggregateContributionFromBridgeProofRecord,
    createAggregateReadyRecord,
    deriveBridgeProofProfileDigest,
    deriveBridgeProofStatementDigest,
    deriveBridgeProofTargetContractDigest,
    selectFirstValidAggregateContributions,
    verifyAggregateContributionStructure,
    verifyAggregateReadyRecordStructure,
} from '../../src/ballot-privacy/index.js';
import { deriveInterpolationCoefficientReport } from '../../src/plaintext-oracle/index.js';

import {
    baseFields,
    createAggregateContributionFixture,
    createAggregateDerivationComponentFixture,
    createSetupEvidenceFixture,
    digest,
    recoveryMapFor,
    sampledPublicRelationCheckPolicy,
    sampledPublicRelationChecks,
    sampledPublicRelationCheckPolicyDigest,
} from './ballot-privacy-aggregate-bridge/fixtures.js';
describe('encrypted aggregate bridge objects', () => {
    it('creates checked bridge proof records from checked kernel bridge evidence', () => {
        const contributorIdentity = 'trustee-1';
        const contributorRosterExternalAcceptanceDigest =
            digest('acceptance-1');
        const aggregateDerivationComponentDigest = digest(
            'aggregate-derivation-1',
        );
        const aggregateShareCommitmentDigest = digest(
            'aggregate-share-commitment-1',
        );
        const aggregateDerivationComponent =
            createAggregateDerivationComponentFixture({
                aggregateDerivationComponentDigest,
                aggregateShareCommitmentDigest,
                contributorIdentity,
                contributorRosterExternalAcceptanceDigest,
                contributorRosterPosition: 1,
            });
        const setupPackage = createSetupEvidenceFixture();
        const bridgeProofProfileDigest = deriveBridgeProofProfileDigest({
            bgvEncryptionProofSubrelation:
                'SealedLatticeDevelopmentCiphertextEquationRelation',
            bridgeProofProfileId: encryptedAggregateBridgeProfileId,
            proofBackend: 'SealedLatticeBridgeRelation',
        });
        const encryptedAggregateShareCiphertextRoot = digest(
            'aggregate-share-ciphertext-1',
        );
        const canonicalBytesHash512 = '4'.repeat(128);
        const canonicalByteLength = 180_781;
        const bridgeProofTargetContractDigest =
            deriveBridgeProofTargetContractDigest({
                aggregateQuotientCoordinateCount:
                    aggregateDerivationComponent.statement.shareVectorWidth,
                aggregateReducedCoordinateCount:
                    aggregateDerivationComponent.statement.shareVectorWidth,
            });
        const bridgeProofStatementDigest = deriveBridgeProofStatementDigest({
            aggregateDerivationComponentDigest,
            aggregateInputEncodingProfileDigest:
                baseFields.aggregateInputEncodingProfileDigest,
            aggregateQuotientCoordinateCount:
                aggregateDerivationComponent.statement.shareVectorWidth,
            aggregateReducedCoordinateCount:
                aggregateDerivationComponent.statement.shareVectorWidth,
            aggregateSelectionPolicyDigest:
                baseFields.aggregateSelectionPolicyDigest,
            aggregateShareCommitmentDigest,
            aggregateToPlaintextBindingStatus:
                'AggregateToPlaintextBindingProofChecked',
            ballotScoreEncodingProfileDigest:
                baseFields.ballotScoreEncodingProfileDigest,
            ballotSetDigest: baseFields.ballotSetDigest,
            ballotShareLayoutProfileDigest:
                baseFields.ballotShareLayoutProfileDigest,
            basisId: 'sealed-lattice-bgv-rns-data-basis-v1',
            bgvBatchEncoderDigest: baseFields.bgvBatchEncoderDigest,
            bgvEncryptionProofStatus: 'BgvCiphertextEquationChecked',
            bgvProfileDigest: baseFields.bgvProfileDigest,
            bgvPublicKeyRoot: baseFields.bgvPublicKeyRoot,
            bgvRandomnessBoundProofStatus:
                'BgvRandomnessErrorSupportPolynomialChecked',
            bridgeClaimClosureStatus: 'BridgeProofClaimClosureMissing',
            bridgeLayoutDigest: baseFields.encryptedAggregateInputLayoutDigest,
            bridgeProofTargetContractDigest,
            bridgeWitnessPrivacyProfileDigest:
                baseFields.bridgeWitnessPrivacyProfileDigest,
            canonicalByteLength,
            canonicalBytesHash512,
            canonicalCiphertextConventionDigest:
                baseFields.canonicalCiphertextConventionDigest,
            ceremonyId: baseFields.ceremonyId,
            ciphertextRoot: digest('bridge-ciphertext-1'),
            coefficientDomainCanonical: true,
            coefficientCount: 32_768,
            collectivePublicKeyRoot: baseFields.collectivePublicKeyRoot,
            contributorActionContextDigest:
                aggregateDerivationComponent.statement
                    .contributorActionContextDigest,
            contributorIdentity,
            contributorRosterExternalAcceptanceDigest,
            contributorRosterPosition: 1,
            optionCount: aggregateDerivationComponent.statement.optionCount,
            participantCount:
                aggregateDerivationComponent.statement.participantCount,
            encodedAggregateLayoutDigest:
                baseFields.encodedAggregateLayoutDigest,
            encodedShareVectorLayoutDigest:
                baseFields.encodedShareVectorLayoutDigest,
            encryptedAggregateBridgeDigest:
                baseFields.encryptedAggregateBridgeDigest,
            encryptedAggregateInputLayoutDigest:
                baseFields.encryptedAggregateInputLayoutDigest,
            encryptedAggregateInputRoot: encryptedAggregateShareCiphertextRoot,
            encryptedAggregateReconstructionDigest:
                baseFields.encryptedAggregateReconstructionDigest,
            encryptedAggregateShareCiphertextRoot,
            encryptedAggregateTargetBasisDataRoot:
                baseFields.encryptedAggregateTargetBasisDataRoot,
            heParamDigest: baseFields.heParamDigest,
            hwangPiopStatus:
                'DeferredUntilSealedLatticeBgvRnsCompatibilityFreeze',
            level: 15,
            manifestDigest: baseFields.manifestDigest,
            plaintextRoot: digest('bridge-plaintext-1'),
            pollSpecDigest: baseFields.pollSpecDigest,
            postVotingClosedContextDigest:
                baseFields.postVotingClosedContextDigest,
            proofProfileDigest: bridgeProofProfileDigest,
            rnsCrtConsistencyProofStatus: 'RnsCrtConsistencyRelationChecked',
            rosterDigest: baseFields.rosterDigest,
            rustBgvBackendProfileDigest: baseFields.rustBgvBackendProfileDigest,
            sampledPublicRelationCheckPolicyDigest,
            sampledOnlyBridgeVerificationAccepted: false,
            setupPackageDigest: baseFields.setupPackageDigest,
            shareCommitmentMessageBoundCertDigest:
                baseFields.shareCommitmentMessageBoundCertDigest,
            shareVectorWidth:
                aggregateDerivationComponent.statement.shareVectorWidth,
            sharedWitnessBindingRequired: true,
            sharedWitnessBindingStatus: 'SharedWitnessBindingRelationChecked',
            sharedWitnessChallengeBitsPerCheck: 64,
            sharedWitnessCheckCount: 2,
            sharedWitnessSoundnessBits: 128,
            sharedWitnessZeroKnowledgeStatus:
                'SharedWitnessZeroKnowledgeResponseDistributionChecked',
            slotCount: 32_768,
            thresholdProfileDigest: baseFields.thresholdProfileDigest,
            topKEvaluatorInputLayoutDigest:
                baseFields.topKEvaluatorInputLayoutDigest,
            votingClosedBoardHeadDigest: baseFields.votingClosedBoardHeadDigest,
        });
        const aggregateRelationChallengeHex = '1'.repeat(48);
        const aggregateRelationCommitmentDigest = digest(
            'aggregate-relation-commitment-1',
        );
        const aggregateRelationSubproofSizeBytes = 384;
        const bridgeProofBytesDigest = digest('bridge-proof-bytes-1');
        const bridgeProofBytesHex = 'ab'.repeat(512);
        const bridgeProofRoot = digest('bridge-proof-root-1');
        const bridgeSharedWitnessProofDigest = digest(
            'bridge-shared-witness-proof-1',
        );
        const sharedWitnessZeroKnowledgeStatusDigest = digest(
            'bridge-shared-witness-zk-status-1',
        );
        const bgvRandomnessBoundProofStatusDigest = digest(
            'bridge-bgv-randomness-bound-status-1',
        );
        const bridgeEncryptionEvidence: PendingBridgeProofRecordFromEvidenceInput['bridgeEncryptionEvidence'] =
            {
                aggregateDerivationComponentDigest,
                aggregateDerivationStatementDigest:
                    aggregateDerivationComponent.statement
                        .aggregateDerivationStatementDigest,
                aggregateQuotientCoordinateCount:
                    aggregateDerivationComponent.statement.shareVectorWidth,
                aggregateReducedCoordinateCount:
                    aggregateDerivationComponent.statement.shareVectorWidth,
                aggregateRelationChallengeHex,
                aggregateRelationCommitmentDigest,
                aggregateRelationSubproofSizeBytes,
                basisId: 'sealed-lattice-bgv-rns-data-basis-v1',
                bgvPublicKeyRoot: baseFields.bgvPublicKeyRoot,
                bridgeProofBytesDigest,
                bridgeProofBytesHex,
                bridgeProofProfileDigest,
                bridgeProofRoot,
                bridgeSharedWitnessProofDigest,
                bridgeProofStatementDigest,
                bridgeProofTargetContractDigest,
                bridgeProofVerificationStatus:
                    'BridgeProofRelationChecked' as const,
                sharedWitnessZeroKnowledgeStatusDigest,
                bgvRandomnessBoundProofStatusDigest,
                canonicalByteLength,
                canonicalBytesHash512,
                canonicalCiphertextConventionDigest:
                    baseFields.canonicalCiphertextConventionDigest,
                ciphertextRoot: digest('bridge-ciphertext-1'),
                coefficientCount: 32_768,
                collectivePublicKeyRoot: baseFields.collectivePublicKeyRoot,
                encryptedAggregateShareCiphertextRoot,
                encryptedAggregateInputRoot:
                    encryptedAggregateShareCiphertextRoot,
                level: 15,
                plaintextRoot: digest('bridge-plaintext-1'),
                profileDigest: baseFields.bgvProfileDigest,
                rustBgvBackendProfileDigest:
                    baseFields.rustBgvBackendProfileDigest,
                sampledPublicRelationCheckPolicy,
                sampledPublicRelationChecks,
                slotCount: 32_768,
            };
        const bridgeEvidenceVerification: PendingBridgeProofRecordFromEvidenceInput['bridgeEvidenceVerification'] =
            {
                aggregateQuotientCoordinateCount:
                    aggregateDerivationComponent.statement.shareVectorWidth,
                aggregateReducedCoordinateCount:
                    aggregateDerivationComponent.statement.shareVectorWidth,
                aggregateRelationChallengeHex,
                aggregateRelationCommitmentDigest,
                aggregateRelationSubproofSizeBytes,
                bridgeEvidenceVerificationStatus:
                    'BridgeProofEvidenceChecked' as const,
                bridgeProofBytesDigest,
                bridgeProofProfileDigest,
                bridgeProofRoot,
                bridgeSharedWitnessProofDigest,
                bridgeProofStatementDigest,
                bridgeProofTargetContractDigest,
                bridgeProofVerificationStatus:
                    'BridgeProofRelationChecked' as const,
                sharedWitnessZeroKnowledgeStatusDigest,
                bgvRandomnessBoundProofStatusDigest,
                encryptedAggregateInputRoot:
                    encryptedAggregateShareCiphertextRoot,
                encryptedAggregateShareCiphertextRoot,
                ok: true as const,
            };

        const bridgeProofRecord =
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence,
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            });

        expect(bridgeProofRecord).toMatchObject({
            aggregateDerivationComponentDigest,
            aggregateShareCommitmentDigest,
            bridgeProofVerificationStatus: 'BridgeProofRelationChecked',
            encryptedAggregateShareCiphertextRoot,
            proofSizeBytes: bridgeProofBytesHex.length / 2,
            proofStatementDigest: bridgeProofStatementDigest,
            bridgeProofTargetContractDigest,
        });
        expect(bridgeProofRecord.proofSizeBytes).toBeGreaterThan(
            aggregateRelationSubproofSizeBytes,
        );
        expect(
            verifyAggregateContributionStructure(
                createAggregateContributionFixture({
                    proofStatus:
                        bridgeProofRecord.bridgeProofVerificationStatus,
                    rosterPosition: 1,
                }),
            ),
        ).toMatchObject({
            backendAvailable: true,
            ok: true,
            unresolvedReason: null,
        });
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence,
                bridgeEvidenceVerification: {
                    ...bridgeEvidenceVerification,
                    bridgeProofRoot: digest('wrong-bridge-proof-root'),
                },
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            }),
        ).toThrow(/bridge proof root/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    bridgeProofStatementDigest: digest(
                        'wrong-bridge-proof-statement',
                    ),
                },
                bridgeEvidenceVerification: {
                    ...bridgeEvidenceVerification,
                    bridgeProofStatementDigest: digest(
                        'wrong-bridge-proof-statement',
                    ),
                },
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            }),
        ).toThrow(/canonical bridge proof statement digest/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    bridgeProofTargetContractDigest: digest(
                        'wrong-bridge-proof-target-contract',
                    ),
                },
                bridgeEvidenceVerification: {
                    ...bridgeEvidenceVerification,
                    bridgeProofTargetContractDigest: digest(
                        'wrong-bridge-proof-target-contract',
                    ),
                },
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            }),
        ).toThrow(/canonical bridge proof target contract digest/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    aggregateRelationChallengeHex: '0'.repeat(48),
                },
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            }),
        ).toThrow(/aggregate relation challenge summary/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    aggregateRelationSubproofSizeBytes:
                        aggregateRelationSubproofSizeBytes + 1,
                },
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            }),
        ).toThrow(/aggregate relation subproof size/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    aggregateReducedCoordinateCount:
                        aggregateDerivationComponent.statement
                            .shareVectorWidth - 1,
                },
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            }),
        ).toThrow(/aggregate reduced coordinate count/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    canonicalBytesHash512: '5'.repeat(128),
                },
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            }),
        ).toThrow(/canonical bridge proof statement digest/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest: digest(
                    'wrong-aggregate-selection-policy',
                ),
                bridgeEncryptionEvidence,
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            }),
        ).toThrow(/canonical bridge proof statement digest/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence,
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileDigest: digest(
                    'wrong-bridge-witness-privacy',
                ),
                heParamDigest: baseFields.heParamDigest,
                setupPackage,
            }),
        ).toThrow(/canonical bridge proof statement digest/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                bridgeEncryptionEvidence,
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileDigest:
                    baseFields.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: digest('wrong-he-param'),
                setupPackage,
            }),
        ).toThrow(/canonical bridge proof statement digest/u);
    });

    it('creates proof-checked aggregate contributions from checked bridge proof records', () => {
        const expectedContribution = createAggregateContributionFixture({
            rosterPosition: 1,
        });

        const contribution = createAggregateContributionFromBridgeProofRecord({
            actionContext: expectedContribution.actionContext,
            boardPosition: expectedContribution.boardPosition,
            bridgeProofRecord: expectedContribution.bridgeProofRecord,
            closeRecordDigest: expectedContribution.closeRecordDigest,
            signature: expectedContribution.signature,
        });

        expect(contribution).toEqual(expectedContribution);
        expect(
            verifyAggregateContributionStructure(contribution),
        ).toMatchObject({
            backendAvailable: true,
            ok: true,
            unresolvedReason: null,
        });
        expect(contribution.bridgeProofRecordDigest).toBe(
            contribution.bridgeProofRecord.bridgeProofRecordDigest,
        );
        expect(contribution.contributorIdentity).toBe('trustee-1');
        expect(contribution.encryptedAggregateShareCiphertextRoot).toBe(
            expectedContribution.bridgeProofRecord
                .encryptedAggregateShareCiphertextRoot,
        );
    });

    it('rejects aggregate contribution creation from pending or mismatched bridge proof records', () => {
        const checkedContribution = createAggregateContributionFixture({
            rosterPosition: 1,
        });
        const pendingContribution = createAggregateContributionFixture({
            proofStatus: 'BridgeProofBackendPending',
            rosterPosition: 1,
        });

        expect(() =>
            createAggregateContributionFromBridgeProofRecord({
                actionContext: pendingContribution.actionContext,
                boardPosition: pendingContribution.boardPosition,
                bridgeProofRecord: pendingContribution.bridgeProofRecord,
                closeRecordDigest: pendingContribution.closeRecordDigest,
                signature: pendingContribution.signature,
            }),
        ).toThrow(/proof-checked bridge proof record/u);

        expect(() =>
            createAggregateContributionFromBridgeProofRecord({
                actionContext: {
                    ...checkedContribution.actionContext,
                    signerIdentity: 'trustee-2',
                },
                boardPosition: checkedContribution.boardPosition,
                bridgeProofRecord: checkedContribution.bridgeProofRecord,
                closeRecordDigest: checkedContribution.closeRecordDigest,
                signature: checkedContribution.signature,
            }),
        ).toThrow(/action context/u);

        expect(() =>
            createAggregateContributionFromBridgeProofRecord({
                actionContext: {
                    ...checkedContribution.actionContext,
                    actionContextDigest: digest('replayed-action-context'),
                    actionSequence:
                        checkedContribution.actionContext.actionSequence + 1,
                    boardSequence:
                        checkedContribution.actionContext.boardSequence + 100,
                },
                boardPosition: checkedContribution.boardPosition,
                bridgeProofRecord: checkedContribution.bridgeProofRecord,
                closeRecordDigest: checkedContribution.closeRecordDigest,
                signature: checkedContribution.signature,
            }),
        ).toThrow(/action context/u);

        expect(() =>
            createAggregateContributionFromBridgeProofRecord({
                actionContext: checkedContribution.actionContext,
                boardPosition: checkedContribution.boardPosition,
                bridgeProofRecord: checkedContribution.bridgeProofRecord,
                closeRecordDigest: 'not-a-digest' as ProtocolDigest,
                signature: checkedContribution.signature,
            }),
        ).toThrow(/close-record digest/u);
    });

    it('rejects aggregate contribution creation when the signature context does not bind the contribution', () => {
        const contribution = createAggregateContributionFixture({
            rosterPosition: 1,
        });

        expect(() =>
            createAggregateContributionFromBridgeProofRecord({
                actionContext: contribution.actionContext,
                boardPosition: contribution.boardPosition,
                bridgeProofRecord: contribution.bridgeProofRecord,
                closeRecordDigest: contribution.closeRecordDigest,
                signature: {
                    ...contribution.signature,
                    signedRoot: {
                        ...contribution.signature.signedRoot,
                        signerIdentity: 'trustee-2',
                    },
                },
            }),
        ).toThrow(/signature envelope/u);

        expect(() =>
            createAggregateContributionFromBridgeProofRecord({
                actionContext: contribution.actionContext,
                boardPosition: contribution.boardPosition,
                bridgeProofRecord: contribution.bridgeProofRecord,
                closeRecordDigest: contribution.closeRecordDigest,
                signature: {
                    ...contribution.signature,
                    signedRoot: {
                        ...contribution.signature.signedRoot,
                        objectType: 'BridgeProofRecord',
                    },
                } as unknown as ProtocolSignatureEnvelope,
            }),
        ).toThrow(/signature envelope/u);

        expect(() =>
            createAggregateContributionFromBridgeProofRecord({
                actionContext: contribution.actionContext,
                boardPosition: contribution.boardPosition,
                bridgeProofRecord: contribution.bridgeProofRecord,
                closeRecordDigest: contribution.closeRecordDigest,
                signature: {
                    ...contribution.signature,
                    signedRoot: {
                        ...contribution.signature.signedRoot,
                        objectRoot: digest('wrong-contribution-root'),
                    },
                },
            }),
        ).toThrow(/signature envelope/u);
    });

    it('rejects structurally valid aggregate contributions with substituted signatures before selection', () => {
        const contribution = createAggregateContributionFixture({
            rosterPosition: 1,
        });
        const otherContribution = createAggregateContributionFixture({
            rosterPosition: 2,
        });
        const substitutedSignatureContribution = {
            ...contribution,
            signature: otherContribution.signature,
        } satisfies AggregateContribution;

        const verification = verifyAggregateContributionStructure(
            substitutedSignatureContribution,
        );
        const selection = selectFirstValidAggregateContributions({
            aggregateContributionQuorum: 1,
            contributions: [substitutedSignatureContribution],
            currentRecoveryEpochMap: recoveryMapFor([
                substitutedSignatureContribution,
            ]),
            expectedAggregateSelectionPolicyDigest:
                baseFields.aggregateSelectionPolicyDigest,
            requiredPostVotingClosedContextDigest:
                baseFields.postVotingClosedContextDigest,
        });

        expect(verification.ok).toBe(false);
        expect(
            verification.refusedObjects.some(
                (refusal) => refusal.code === 'InvalidSignedRoot',
            ),
        ).toBe(true);
        expect(selection.ok).toBe(false);
        expect(selection.selectedContributions).toEqual([]);
    });

    it('derives stable witness-clean contribution hashes and rejects stale mutations', () => {
        const contribution = createAggregateContributionFixture({
            rosterPosition: 1,
        });
        const changedContribution = createAggregateContributionFixture({
            encryptedAggregateShareCiphertextRoot: digest(
                'changed-share-ciphertext',
            ),
            rosterPosition: 1,
        });
        const staleContribution = {
            ...contribution,
            encryptedAggregateShareCiphertextRoot: digest(
                'stale-share-ciphertext',
            ),
        };

        expect(
            verifyAggregateContributionStructure(contribution),
        ).toMatchObject({
            backendAvailable: true,
            ok: true,
            unresolvedReason: null,
        });
        expect(contribution.aggregateContributionDigest).not.toBe(
            changedContribution.aggregateContributionDigest,
        );
        expect(contribution).not.toHaveProperty('bridgeWitness');
        expect(contribution).not.toHaveProperty('bgvPlaintext');
        expect(contribution).not.toHaveProperty('encryptionRandomness');
        expect(
            verifyAggregateContributionStructure(
                staleContribution as AggregateContribution,
            ),
        ).toMatchObject({
            ok: false,
        });
    });

    it('rejects public witness fields anywhere in the aggregate contribution object', () => {
        const contribution = createAggregateContributionFixture({
            rosterPosition: 1,
        });
        for (const forbiddenFieldName of forbiddenPublicWitnessFieldNames) {
            const leakyContribution = {
                ...contribution,
                bridgeProofRecord: {
                    ...contribution.bridgeProofRecord,
                    [forbiddenFieldName]: ['leaked witness material'],
                },
            };

            const verification = verifyAggregateContributionStructure(
                leakyContribution as AggregateContribution,
            );

            expect(verification.ok, forbiddenFieldName).toBe(false);
            expect(
                verification.refusedObjects.some((refusal) =>
                    refusal.message.includes(forbiddenFieldName),
                ),
                forbiddenFieldName,
            ).toBe(true);
        }

        const cyclicContainer: Record<string, unknown> = {};
        cyclicContainer.self = cyclicContainer;
        const leakyContribution = {
            ...contribution,
            bridgeProofRecord: {
                ...contribution.bridgeProofRecord,
                bgvPlaintext: [1, 2, 3],
            },
            cyclicContainer,
        };

        const verification = verifyAggregateContributionStructure(
            leakyContribution as AggregateContribution,
        );

        expect(verification.ok).toBe(false);
        expect(
            verification.refusedObjects.some((refusal) =>
                refusal.message.includes('bgvPlaintext'),
            ),
        ).toBe(true);
        expect(
            verification.refusedObjects.some((refusal) =>
                refusal.message.includes('cyclic object references'),
            ),
        ).toBe(true);
    });

    it('selects the first proof-valid aggregate contributors and keeps later arrivals out of the selected order hash', () => {
        const earlyContribution = createAggregateContributionFixture({
            boardSequence: 10,
            rosterPosition: 1,
        });
        const secondContribution = createAggregateContributionFixture({
            boardSequence: 20,
            rosterPosition: 2,
        });
        const lateContribution = createAggregateContributionFixture({
            boardSequence: 30,
            rosterPosition: 3,
        });
        const laterExtraContribution = createAggregateContributionFixture({
            boardSequence: 100,
            rosterPosition: 4,
        });
        const recoveryMap = recoveryMapFor([
            earlyContribution,
            secondContribution,
            lateContribution,
            laterExtraContribution,
        ]);

        const selection = selectFirstValidAggregateContributions({
            aggregateContributionQuorum: 2,
            contributions: [
                lateContribution,
                secondContribution,
                earlyContribution,
            ],
            currentRecoveryEpochMap: recoveryMap,
            expectedAggregateSelectionPolicyDigest:
                baseFields.aggregateSelectionPolicyDigest,
            requiredPostVotingClosedContextDigest:
                baseFields.postVotingClosedContextDigest,
        });
        const selectionWithLateExtra = selectFirstValidAggregateContributions({
            aggregateContributionQuorum: 2,
            contributions: [
                lateContribution,
                laterExtraContribution,
                secondContribution,
                earlyContribution,
            ],
            currentRecoveryEpochMap: recoveryMap,
            expectedAggregateSelectionPolicyDigest:
                baseFields.aggregateSelectionPolicyDigest,
            requiredPostVotingClosedContextDigest:
                baseFields.postVotingClosedContextDigest,
        });

        expect(selection.ok).toBe(true);
        expect(
            selection.selectedContributions.map(
                (contribution) => contribution.contributorRosterPosition,
            ),
        ).toEqual([1, 2]);
        expect(selectionWithLateExtra.firstValidOrderDigest).toBe(
            selection.firstValidOrderDigest,
        );
    });

    it('rejects conflicting duplicate identities, stale recovery epochs, and stale contexts', () => {
        const contribution = createAggregateContributionFixture({
            rosterPosition: 1,
        });
        const duplicateIdentityContribution =
            createAggregateContributionFixture({
                encryptedAggregateShareCiphertextRoot: digest(
                    'duplicate-identity-ciphertext',
                ),
                rosterPosition: 1,
            });
        const staleRecoveryContribution = createAggregateContributionFixture({
            recoveryEpoch: 0,
            rosterPosition: 2,
        });
        const wrongContextContribution = createAggregateContributionFixture({
            contextDigest: digest('wrong-post-voting-context'),
            rosterPosition: 3,
        });

        expect(
            selectFirstValidAggregateContributions({
                aggregateContributionQuorum: 1,
                contributions: [contribution, duplicateIdentityContribution],
                currentRecoveryEpochMap: recoveryMapFor([contribution]),
                expectedAggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                requiredPostVotingClosedContextDigest:
                    baseFields.postVotingClosedContextDigest,
            }).refusedObjects.some(
                (refusal) => refusal.code === 'ConflictingFirstValidObject',
            ),
        ).toBe(true);

        expect(
            selectFirstValidAggregateContributions({
                aggregateContributionQuorum: 1,
                contributions: [staleRecoveryContribution],
                currentRecoveryEpochMap: {
                    [staleRecoveryContribution.contributorIdentity]: {
                        currentDeviceEpoch: 1,
                        currentRecoveryEpoch: 1,
                        signerIdentity:
                            staleRecoveryContribution.contributorIdentity,
                    },
                },
                expectedAggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                requiredPostVotingClosedContextDigest:
                    baseFields.postVotingClosedContextDigest,
            }).refusedObjects.some(
                (refusal) => refusal.code === 'StaleRecoveryEpoch',
            ),
        ).toBe(true);

        expect(
            selectFirstValidAggregateContributions({
                aggregateContributionQuorum: 1,
                contributions: [wrongContextContribution],
                currentRecoveryEpochMap: recoveryMapFor([
                    wrongContextContribution,
                ]),
                expectedAggregateSelectionPolicyDigest:
                    baseFields.aggregateSelectionPolicyDigest,
                requiredPostVotingClosedContextDigest:
                    baseFields.postVotingClosedContextDigest,
            }).refusedObjects.some(
                (refusal) => refusal.code === 'FirstValidContextMismatch',
            ),
        ).toBe(true);
    });

    it('creates aggregate-ready records from recomputed interpolation coefficients', () => {
        const selectedContributions = [
            createAggregateContributionFixture({ rosterPosition: 1 }),
            createAggregateContributionFixture({ rosterPosition: 2 }),
        ];
        const selection = selectFirstValidAggregateContributions({
            aggregateContributionQuorum: 2,
            contributions: selectedContributions,
            currentRecoveryEpochMap: recoveryMapFor(selectedContributions),
            expectedAggregateSelectionPolicyDigest:
                baseFields.aggregateSelectionPolicyDigest,
            requiredPostVotingClosedContextDigest:
                baseFields.postVotingClosedContextDigest,
        });
        const coefficientReport = deriveInterpolationCoefficientReport({
            contributorRosterPositions: [1, 2],
            rosterSize: 20,
            threshold: 2,
        });
        const record = createAggregateReadyRecord({
            aggregateContributionQuorum: 2,
            firstValidOrderDigest:
                selection.firstValidOrderDigest ?? digest('missing'),
            rosterSize: 20,
            selectedContributions: selection.selectedContributions,
            suppliedInterpolationCoefficientReport: coefficientReport,
        });
        const repeatedRecord = createAggregateReadyRecord({
            aggregateContributionQuorum: 2,
            firstValidOrderDigest:
                selection.firstValidOrderDigest ?? digest('missing'),
            rosterSize: 20,
            selectedContributions: selection.selectedContributions,
        });
        const changedContribution = createAggregateContributionFixture({
            encryptedAggregateShareCiphertextRoot: digest(
                'changed-ready-ciphertext',
            ),
            rosterPosition: 2,
        });
        const changedSelection = selectFirstValidAggregateContributions({
            aggregateContributionQuorum: 2,
            contributions: [selectedContributions[0], changedContribution],
            currentRecoveryEpochMap: recoveryMapFor([
                selectedContributions[0],
                changedContribution,
            ]),
            expectedAggregateSelectionPolicyDigest:
                baseFields.aggregateSelectionPolicyDigest,
            requiredPostVotingClosedContextDigest:
                baseFields.postVotingClosedContextDigest,
        });
        const changedRecord = createAggregateReadyRecord({
            aggregateContributionQuorum: 2,
            firstValidOrderDigest:
                changedSelection.firstValidOrderDigest ?? digest('missing'),
            rosterSize: 20,
            selectedContributions: changedSelection.selectedContributions,
        });
        const mismatchedReport = {
            ...coefficientReport,
            coefficients: [
                {
                    ...coefficientReport.coefficients[0],
                    coefficient:
                        (coefficientReport.coefficients[0]?.coefficient ?? 0) +
                        1,
                },
                ...coefficientReport.coefficients.slice(1),
            ],
        };

        expect(selection.ok).toBe(true);
        expect(record.interpolationCoefficientReportDigest).toBe(
            coefficientReport.reportDigest,
        );
        expect(record.selectedContributorRosterPositions).toEqual([1, 2]);
        expect(record.aggregateReadyRecordDigest).toBe(
            repeatedRecord.aggregateReadyRecordDigest,
        );
        expect(changedRecord.aggregateReadyRecordDigest).not.toBe(
            record.aggregateReadyRecordDigest,
        );
        expect(() =>
            createAggregateReadyRecord({
                aggregateContributionQuorum: 2,
                firstValidOrderDigest: digest('forged-first-valid-order'),
                rosterSize: 20,
                selectedContributions: selection.selectedContributions,
            }),
        ).toThrow(/first-valid order digest/u);
        expect(() =>
            createAggregateReadyRecord({
                aggregateContributionQuorum: 2,
                firstValidOrderDigest:
                    selection.firstValidOrderDigest ?? digest('missing'),
                rosterSize: 20,
                selectedContributions: selection.selectedContributions,
                suppliedInterpolationCoefficientReport: mismatchedReport,
            }),
        ).toThrow(/does not match recomputation/u);

        const {
            aggregateReadyRecordDigest: originalAggregateReadyRecordDigest,
            ...recordWithoutDigest
        } = record;
        void originalAggregateReadyRecordDigest;
        const forgedFirstValidOrderDigest = digest(
            'forged-verifier-first-valid-order',
        );
        const forgedRecordPayload: Omit<
            AggregateReadyRecord,
            'aggregateReadyRecordDigest'
        > = {
            ...recordWithoutDigest,
            encryptedAggregateReconstructionRoot:
                deriveEncryptedAggregateReconstructionRoot({
                    aggregateSelectionPolicyDigest:
                        record.aggregateSelectionPolicyDigest,
                    encryptedAggregateReconstructionDigest:
                        record.encryptedAggregateReconstructionDigest,
                    encryptedAggregateShareCiphertextRoots:
                        record.encryptedAggregateShareCiphertextRoots,
                    firstValidOrderDigest: forgedFirstValidOrderDigest,
                    interpolationCoefficientReportDigest:
                        record.interpolationCoefficientReportDigest,
                    selectedAggregateContributionDigests:
                        record.selectedAggregateContributionDigests,
                }),
            firstValidOrderDigest: forgedFirstValidOrderDigest,
        };
        const forgedRecord = {
            ...forgedRecordPayload,
            aggregateReadyRecordDigest:
                deriveAggregateReadyRecordDigest(forgedRecordPayload),
        };

        expect(verifyAggregateReadyRecordStructure(forgedRecord).ok).toBe(
            false,
        );
    });
});
