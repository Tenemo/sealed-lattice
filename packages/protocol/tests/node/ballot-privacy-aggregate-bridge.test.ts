import {
    encryptedAggregateBridgeProfileId,
    type AggregateContribution,
    type AggregateReadyRecord,
    type ProtocolSignatureEnvelope,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    baseFields,
    createAggregateContributionFixture,
    createAggregateDerivationComponentFixture,
    createSetupEvidenceFixture,
    hash,
    recoveryMapFor,
    sampledPublicRelationCheckPolicy,
    sampledPublicRelationChecks,
    sampledPublicRelationCheckPolicyHash,
} from './ballot-privacy-aggregate-bridge/fixtures.js';

import {
    deriveAggregateReadyRecordHash,
    deriveEncryptedAggregateReconstructionRoot,
} from '#packages/protocol/src/ballot-privacy/aggregate-bridge/hashes.js';
import {
    createPendingBridgeProofRecordFromBridgeEvidence,
    type PendingBridgeProofRecordFromEvidenceInput,
} from '#packages/protocol/src/ballot-privacy/aggregate-bridge/structure-verification.js';
import { forbiddenPublicWitnessFieldNames } from '#packages/protocol/src/ballot-privacy/aggregate-derivation/constants.js';
import {
    createAggregateContributionFromBridgeProofRecord,
    createAggregateReadyRecord,
    deriveBridgeProofChallengeContextHash,
    deriveBridgeProofProfileHash,
    deriveBridgeProofStatementHash,
    deriveBridgeProofTargetContractHash,
    selectFirstValidAggregateContributions,
    verifyAggregateContributionStructure,
    verifyAggregateReadyRecordStructure,
} from '#packages/protocol/src/ballot-privacy/index.js';
import { deriveInterpolationCoefficientReport } from '#packages/protocol/src/plaintext-oracle/index.js';

describe('encrypted aggregate bridge objects', () => {
    it('creates checked bridge proof records from checked kernel bridge evidence', () => {
        const contributorIdentity = 'trustee-1';
        const contributorRosterExternalAcceptanceHash = hash('acceptance-1');
        const aggregateDerivationComponentHash = hash('aggregate-derivation-1');
        const aggregateShareCommitmentHash = hash(
            'aggregate-share-commitment-1',
        );
        const aggregateDerivationComponent =
            createAggregateDerivationComponentFixture({
                aggregateDerivationComponentHash,
                aggregateShareCommitmentHash,
                contributorIdentity,
                contributorRosterExternalAcceptanceHash,
                contributorRosterPosition: 1,
            });
        const setupPackage = createSetupEvidenceFixture();
        const bridgeProofProfileHash = deriveBridgeProofProfileHash({
            bgvEncryptionKeyMaterialKind:
                'passive-transcript-derived-collective-public-key',
            bgvEncryptionProofSubrelation:
                'SealedLatticePassiveCollectiveCiphertextEquationRelation',
            bridgeProofProfileId: encryptedAggregateBridgeProfileId,
            claimBearingBridgeEncryption: false,
            developmentKeyOnly: false,
            proofBackend: 'SealedLatticeBridgeRelation',
            thresholdDecryptable: true,
        });
        const encryptedAggregateShareCiphertextRoot = hash(
            'aggregate-share-ciphertext-1',
        );
        const canonicalBytesHash512 = '4'.repeat(128);
        const canonicalByteLength = 180_781;
        const bridgeProofTargetContractHash =
            deriveBridgeProofTargetContractHash({
                aggregateQuotientCoordinateCount:
                    aggregateDerivationComponent.statement.shareVectorWidth,
                aggregateReducedCoordinateCount:
                    aggregateDerivationComponent.statement.shareVectorWidth,
                aggregateDerivationVerificationScope:
                    'AggregateDerivationFullVerificationChecked',
                bridgeClaimClosureStatus: 'BridgeProofClaimClosureMissing',
                claimBearingBridgeEncryption: false,
            });
        const batchEncodingBoundCertificateHash = hash(
            'batch-encoding-bound-certificate-1',
        );
        const bridgeProofStatementHash = deriveBridgeProofStatementHash({
            aggregateDerivationComponentHash,
            aggregateInputEncodingProfileHash:
                baseFields.aggregateInputEncodingProfileHash,
            aggregateQuotientCoordinateCount:
                aggregateDerivationComponent.statement.shareVectorWidth,
            aggregateReducedCoordinateCount:
                aggregateDerivationComponent.statement.shareVectorWidth,
            aggregateSelectionPolicyHash:
                baseFields.aggregateSelectionPolicyHash,
            aggregateShareCommitmentHash,
            aggregateToPlaintextBindingStatus:
                'AggregateToPlaintextModularBindingChecked',
            ballotScoreEncodingProfileHash:
                baseFields.ballotScoreEncodingProfileHash,
            ballotSetHash: baseFields.ballotSetHash,
            ballotShareLayoutProfileHash:
                baseFields.ballotShareLayoutProfileHash,
            basisId: 'sealed-lattice-bgv-rns-data-basis-v1',
            batchEncodingBoundCertificateHash,
            bgvBatchEncoderHash: baseFields.bgvBatchEncoderHash,
            bgvEncryptionKeyMaterialKind:
                'passive-transcript-derived-collective-public-key',
            bgvEncryptionProofStatus: 'BgvCiphertextEquationChecked',
            bgvProfileHash: baseFields.bgvProfileHash,
            bgvPublicKeyRoot: baseFields.bgvPublicKeyRoot,
            bgvRandomnessBoundProofStatus:
                'BgvRandomnessErrorSupportPolynomialChecked',
            bridgeClaimClosureStatus: 'BridgeProofClaimClosureMissing',
            bridgeLayoutHash: baseFields.encryptedAggregateInputLayoutHash,
            bridgeProofTargetContractHash,
            bridgeWitnessPrivacyProfileHash:
                baseFields.bridgeWitnessPrivacyProfileHash,
            canonicalByteLength,
            canonicalBytesHash512,
            canonicalCiphertextConventionHash:
                baseFields.canonicalCiphertextConventionHash,
            ceremonyId: baseFields.ceremonyId,
            ciphertextRoot: hash('bridge-ciphertext-1'),
            claimBearingBridgeEncryption: false,
            coefficientDomainCanonical: true,
            coefficientCount: 32_768,
            collectivePublicKeyRoot: baseFields.collectivePublicKeyRoot,
            collectivePublicKeyCoefficientRoot:
                baseFields.collectivePublicKeyCoefficientRoot,
            contributorActionContextHash:
                aggregateDerivationComponent.statement
                    .contributorActionContextHash,
            contributorIdentity,
            contributorRosterExternalAcceptanceHash,
            contributorRosterPosition: 1,
            developmentKeyOnly: false,
            optionCount: aggregateDerivationComponent.statement.optionCount,
            participantCount:
                aggregateDerivationComponent.statement.participantCount,
            encodedAggregateLayoutHash: baseFields.encodedAggregateLayoutHash,
            encodedShareVectorLayoutHash:
                baseFields.encodedShareVectorLayoutHash,
            encryptedAggregateBridgeHash:
                baseFields.encryptedAggregateBridgeHash,
            encryptedAggregateInputLayoutHash:
                baseFields.encryptedAggregateInputLayoutHash,
            encryptedAggregateInputRoot: encryptedAggregateShareCiphertextRoot,
            encryptedAggregateReconstructionHash:
                baseFields.encryptedAggregateReconstructionHash,
            encryptedAggregateShareCiphertextRoot,
            encryptedAggregateTargetBasisRoot:
                baseFields.encryptedAggregateTargetBasisRoot,
            heParamHash: baseFields.heParamHash,
            hwangPiopStatus: 'DeferredUntilSealedLatticeBgvRnsProfileFreeze',
            level: 15,
            manifestHash: baseFields.manifestHash,
            aggregateDerivationVerificationScope:
                'AggregateDerivationFullVerificationChecked',
            plaintextCanonicalLiftProofStatus:
                'PlaintextCanonicalLiftProofChecked',
            plaintextCoefficientBindingCommitmentHash: hash(
                'plaintext-coefficient-binding-1',
            ),
            plaintextEncodingBoundCertificateHash:
                batchEncodingBoundCertificateHash,
            plaintextEncodingProofModuli: [
                140_737_487_306_753, 140_737_486_716_929,
            ],
            plaintextEncodingProofModulusProduct:
                '19807040250408114080301121537',
            plaintextEncodingProofModulusProductBitsFloor: 93,
            plaintextRoot: hash('bridge-plaintext-1'),
            pollSpecHash: baseFields.pollSpecHash,
            postVotingClosedContextHash: baseFields.postVotingClosedContextHash,
            proofFriendlyPlaintextBindingStatus:
                'ProofFriendlyPlaintextCoefficientBindingRelationChecked',
            proofFriendlyPlaintextLiftBindingHash: hash(
                'plaintext-lift-binding-1',
            ),
            proofFriendlyPlaintextLiftBindingStatus:
                'ProofFriendlyPlaintextCoefficientLiftBindingChecked',
            proofProfileHash: bridgeProofProfileHash,
            rnsCrtConsistencyProofStatus: 'RnsCrtConsistencyRelationChecked',
            rosterHash: baseFields.rosterHash,
            rustBgvBackendProfileHash: baseFields.rustBgvBackendProfileHash,
            sampledPublicRelationCheckPolicyHash,
            sampledOnlyBridgeVerificationAccepted: false,
            setupPackageHash: baseFields.setupPackageHash,
            shareCommitmentMessageBoundCertHash:
                baseFields.shareCommitmentMessageBoundCertHash,
            shareVectorWidth:
                aggregateDerivationComponent.statement.shareVectorWidth,
            sharedWitnessBindingRequired: true,
            sharedWitnessBindingStatus: 'SharedWitnessBindingRelationChecked',
            sharedWitnessChallengeBitsPerCheck: 46,
            sharedWitnessCheckCount: 5,
            sharedWitnessChallengeSamplingModel:
                'nonzero-weakest-relation-46-bit-rejection-sampled-from-64-bit-lanes-v1',
            sharedWitnessRejectionAttemptLimit: 64,
            sharedWitnessGrindingDiscountBitsPerCheck: 6,
            sharedWitnessRejectionRetryLossBits: 30,
            sharedWitnessFullMatrixUnionBoundBits: 9,
            sharedWitnessRandomOracleQueryBoundBits: 32,
            sharedWitnessRandomOracleAccountingModel:
                'classical-random-oracle-query-loss-with-explicit-bound-v1',
            sharedWitnessQromAccountingStatus:
                'QromAccountingNotProvidedForHandoff',
            sharedWitnessProofSystemLossBits: 0,
            sharedWitnessChallengeBiasAccountingModel:
                'crt-product-challenge-reduced-to-aggregate-field-with-one-bit-loss-v1',
            sharedWitnessChallengeBiasBits: 1,
            sharedWitnessAdditionalRelationLossBits: 9,
            sharedWitnessBgvSupportRelation:
                'BgvRandomnessErrorSupportPolynomialBatchRelation',
            sharedWitnessBgvSupportChallengeDistribution:
                'shared-witness-challenge-reduced-modulo-bgv-support-prime-v1',
            sharedWitnessBgvSupportCancellationModel:
                'random-linear-batched-support-cancellation-accounted-by-union-loss-v1',
            sharedWitnessBgvSupportUnionBoundBits: 9,
            sharedWitnessTargetBindingSoundnessBits: 128,
            sharedWitnessRawWeakestRelationSoundnessBitsFloor: 230,
            sharedWitnessEffectiveBindingSoundnessBitsFloor: 149,
            sharedWitnessEffectiveBindingBelowTarget: false,
            sharedWitnessWeakestRelation: 'AggregateReductionFieldRelation',
            sharedWitnessWeakestRelationModel:
                'aggregate-proof-ring-effective-binding-floor-v1',
            sharedWitnessWeakestRelationEffectiveModulus: '70368744177829',
            sharedWitnessWeakestRelationBitsPerCheck: 46,
            batchIntegerLiftProofModuli: [
                140_737_487_306_753, 140_737_486_716_929,
            ],
            batchIntegerLiftProofModulusProduct:
                '19807040250408114080301121537',
            batchIntegerLiftProofModulusProductBitsFloor: 93,
            sharedWitnessZeroKnowledgeStatus:
                'SharedWitnessZeroKnowledgeResponseDistributionChecked',
            slotCount: 32_768,
            thresholdProfileHash: baseFields.thresholdProfileHash,
            thresholdDecryptable: true,
            topKEvaluatorInputLayoutHash:
                baseFields.topKEvaluatorInputLayoutHash,
            votingClosedBoardHeadHash: baseFields.votingClosedBoardHeadHash,
        });
        const bridgeProofChallengeContextHash =
            deriveBridgeProofChallengeContextHash({
                bridgeProofProfileHash,
                bridgeProofStatementHash,
                bridgeProofTargetContractHash,
            });
        const aggregateRelationChallengeHex = '1'.repeat(48);
        const aggregateRelationCommitmentHash = hash(
            'aggregate-relation-commitment-1',
        );
        const aggregateRelationSubproofSizeBytes = 384;
        const bridgeProofBytesHash = hash('bridge-proof-bytes-1');
        const bridgeProofBytesHex = 'ab'.repeat(512);
        const bridgeProofRoot = hash('bridge-proof-root-1');
        const bridgeSharedWitnessProofHash = hash(
            'bridge-shared-witness-proof-1',
        );
        const sharedWitnessZeroKnowledgeStatusHash = hash(
            'bridge-shared-witness-zk-status-1',
        );
        const bgvRandomnessBoundProofStatusHash = hash(
            'bridge-bgv-randomness-bound-status-1',
        );
        const plaintextCoefficientBindingCommitmentHash = hash(
            'plaintext-coefficient-binding-1',
        );
        const proofFriendlyPlaintextLiftBindingHash = hash(
            'plaintext-lift-binding-1',
        );
        const aggregateBridgeRelationHandoffRoot = hash(
            'aggregate-bridge-relation-handoff-1',
        );
        const randomnessSourceEvidence = {
            callerSuppliedDevelopmentRandomness: false,
            claimBearingEntropyEvidence: false,
            encryptionRandomnessSeedSource: 'fresh-csprng',
            objectType: 'AggregateBridgeRandomnessSourceEvidence',
            objectVersion: 1,
            proverRandomnessSource: 'fresh-csprng',
        } as const;
        const bridgeEncryptionEvidence: PendingBridgeProofRecordFromEvidenceInput['bridgeEncryptionEvidence'] =
            {
                aggregateDerivationComponentHash,
                aggregateDerivationStatementHash:
                    aggregateDerivationComponent.statement
                        .aggregateDerivationStatementHash,
                aggregateQuotientCoordinateCount:
                    aggregateDerivationComponent.statement.shareVectorWidth,
                aggregateReducedCoordinateCount:
                    aggregateDerivationComponent.statement.shareVectorWidth,
                aggregateRelationChallengeHex,
                aggregateRelationCommitmentHash,
                aggregateRelationSubproofSizeBytes,
                basisId: 'sealed-lattice-bgv-rns-data-basis-v1',
                batchEncodingBoundCertificateHash,
                bgvEncryptionKeyMaterialKind:
                    'passive-transcript-derived-collective-public-key',
                bgvPublicKeyRoot: baseFields.bgvPublicKeyRoot,
                bridgeProofBytesHash,
                bridgeProofBytesHex,
                bridgeProofProfileHash,
                bridgeProofRoot,
                bridgeSharedWitnessProofHash,
                bridgeProofChallengeContextHash,
                bridgeProofStatementHash,
                bridgeProofTargetContractHash,
                bridgeProofVerificationStatus:
                    'BridgeProofRelationChecked' as const,
                bridgeClaimClosureVerified: false,
                bridgeClaimVerificationStatus:
                    'BridgeProofClaimClosureMissing' as const,
                claimBearingBridgeEncryption: false,
                plaintextCoefficientBindingCommitmentHash,
                proofFriendlyPlaintextLiftBindingHash,
                aggregateBridgeRelationHandoffRoot,
                aggregateDerivationVerificationScope:
                    'AggregateDerivationFullVerificationChecked' as const,
                plaintextCanonicalLiftProofStatus:
                    'PlaintextCanonicalLiftProofChecked' as const,
                sharedWitnessZeroKnowledgeStatusHash,
                bgvRandomnessBoundProofStatusHash,
                canonicalByteLength,
                canonicalBytesHash512,
                canonicalCiphertextConventionHash:
                    baseFields.canonicalCiphertextConventionHash,
                ciphertextRoot: hash('bridge-ciphertext-1'),
                coefficientCount: 32_768,
                collectivePublicKeyRoot: baseFields.collectivePublicKeyRoot,
                collectivePublicKeyCoefficientRoot:
                    baseFields.collectivePublicKeyCoefficientRoot,
                developmentKeyOnly: false,
                proverRandomnessSource: 'fresh-csprng',
                encryptionRandomnessSeedSource: 'fresh-csprng',
                randomnessSourceEvidence,
                encryptedAggregateShareCiphertextRoot,
                encryptedAggregateInputRoot:
                    encryptedAggregateShareCiphertextRoot,
                level: 15,
                plaintextRoot: hash('bridge-plaintext-1'),
                profileHash: baseFields.bgvProfileHash,
                rustBgvBackendProfileHash: baseFields.rustBgvBackendProfileHash,
                sampledPublicRelationCheckPolicy,
                sampledPublicRelationChecks,
                slotCount: 32_768,
                thresholdDecryptable: true,
            };
        const bridgeEvidenceVerification: PendingBridgeProofRecordFromEvidenceInput['bridgeEvidenceVerification'] =
            {
                aggregateQuotientCoordinateCount:
                    aggregateDerivationComponent.statement.shareVectorWidth,
                aggregateReducedCoordinateCount:
                    aggregateDerivationComponent.statement.shareVectorWidth,
                aggregateRelationChallengeHex,
                aggregateRelationCommitmentHash,
                aggregateRelationSubproofSizeBytes,
                bgvEncryptionKeyMaterialKind:
                    'passive-transcript-derived-collective-public-key',
                bridgeEvidenceVerificationStatus:
                    'BridgeProofEvidenceChecked' as const,
                bridgeProofBytesHash,
                bridgeProofProfileHash,
                bridgeProofRoot,
                bridgeSharedWitnessProofHash,
                bridgeProofChallengeContextHash,
                bridgeProofStatementHash,
                bridgeProofTargetContractHash,
                bridgeProofVerificationStatus:
                    'BridgeProofRelationChecked' as const,
                bridgeClaimClosureVerified: false,
                bridgeClaimVerificationStatus:
                    'BridgeProofClaimClosureMissing' as const,
                claimBearingBridgeEncryption: false,
                plaintextCoefficientBindingCommitmentHash,
                proofFriendlyPlaintextLiftBindingHash,
                aggregateBridgeRelationHandoffRoot,
                aggregateDerivationVerificationScope:
                    'AggregateDerivationFullVerificationChecked' as const,
                plaintextCanonicalLiftProofStatus:
                    'PlaintextCanonicalLiftProofChecked' as const,
                sharedWitnessZeroKnowledgeStatusHash,
                bgvRandomnessBoundProofStatusHash,
                encryptedAggregateInputRoot:
                    encryptedAggregateShareCiphertextRoot,
                encryptedAggregateShareCiphertextRoot,
                collectivePublicKeyCoefficientRoot:
                    baseFields.collectivePublicKeyCoefficientRoot,
                developmentKeyOnly: false,
                proverRandomnessSource: 'fresh-csprng',
                encryptionRandomnessSeedSource: 'fresh-csprng',
                randomnessSourceEvidence,
                ok: true as const,
                thresholdDecryptable: true,
            };

        const bridgeProofRecord =
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyHash:
                    baseFields.aggregateSelectionPolicyHash,
                bridgeEncryptionEvidence,
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileHash:
                    baseFields.bridgeWitnessPrivacyProfileHash,
                heParamHash: baseFields.heParamHash,
                setupPackage,
            });

        expect(bridgeProofRecord).toMatchObject({
            aggregateDerivationComponentHash,
            aggregateShareCommitmentHash,
            bridgeProofVerificationStatus: 'BridgeProofRelationChecked',
            encryptedAggregateShareCiphertextRoot,
            proofSizeBytes: bridgeProofBytesHex.length / 2,
            proofStatementHash: bridgeProofStatementHash,
            bridgeProofChallengeContextHash,
            bridgeProofTargetContractHash,
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
                aggregateSelectionPolicyHash:
                    baseFields.aggregateSelectionPolicyHash,
                bridgeEncryptionEvidence,
                bridgeEvidenceVerification: {
                    ...bridgeEvidenceVerification,
                    bridgeProofRoot: hash('wrong-bridge-proof-root'),
                },
                bridgeWitnessPrivacyProfileHash:
                    baseFields.bridgeWitnessPrivacyProfileHash,
                heParamHash: baseFields.heParamHash,
                setupPackage,
            }),
        ).toThrow(/bridge proof root/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyHash:
                    baseFields.aggregateSelectionPolicyHash,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    bridgeProofStatementHash: hash(
                        'wrong-bridge-proof-statement',
                    ),
                },
                bridgeEvidenceVerification: {
                    ...bridgeEvidenceVerification,
                    bridgeProofStatementHash: hash(
                        'wrong-bridge-proof-statement',
                    ),
                },
                bridgeWitnessPrivacyProfileHash:
                    baseFields.bridgeWitnessPrivacyProfileHash,
                heParamHash: baseFields.heParamHash,
                setupPackage,
            }),
        ).toThrow(/canonical bridge proof statement hash/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyHash:
                    baseFields.aggregateSelectionPolicyHash,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    bridgeProofChallengeContextHash: hash(
                        'wrong-bridge-proof-challenge-context',
                    ),
                },
                bridgeEvidenceVerification: {
                    ...bridgeEvidenceVerification,
                    bridgeProofChallengeContextHash: hash(
                        'wrong-bridge-proof-challenge-context',
                    ),
                },
                bridgeWitnessPrivacyProfileHash:
                    baseFields.bridgeWitnessPrivacyProfileHash,
                heParamHash: baseFields.heParamHash,
                setupPackage,
            }),
        ).toThrow(/canonical bridge proof challenge context hash/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyHash:
                    baseFields.aggregateSelectionPolicyHash,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                },
                bridgeEvidenceVerification: {
                    ...bridgeEvidenceVerification,
                    bridgeProofTargetContractHash: hash(
                        'wrong-bridge-proof-target-contract',
                    ),
                },
                bridgeWitnessPrivacyProfileHash:
                    baseFields.bridgeWitnessPrivacyProfileHash,
                heParamHash: baseFields.heParamHash,
                setupPackage,
            }),
        ).toThrow(/bridge proof target contract hash/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyHash:
                    baseFields.aggregateSelectionPolicyHash,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    bridgeProofTargetContractHash: hash(
                        'wrong-agreed-bridge-proof-target-contract',
                    ),
                },
                bridgeEvidenceVerification: {
                    ...bridgeEvidenceVerification,
                    bridgeProofTargetContractHash: hash(
                        'wrong-agreed-bridge-proof-target-contract',
                    ),
                },
                bridgeWitnessPrivacyProfileHash:
                    baseFields.bridgeWitnessPrivacyProfileHash,
                heParamHash: baseFields.heParamHash,
                setupPackage,
            }),
        ).toThrow(/canonical bridge proof statement hash/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyHash:
                    baseFields.aggregateSelectionPolicyHash,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    collectivePublicKeyCoefficientRoot: hash(
                        'wrong-collective-public-key-coefficients',
                    ),
                },
                bridgeEvidenceVerification: {
                    ...bridgeEvidenceVerification,
                    collectivePublicKeyCoefficientRoot: hash(
                        'wrong-collective-public-key-coefficients',
                    ),
                },
                bridgeWitnessPrivacyProfileHash:
                    baseFields.bridgeWitnessPrivacyProfileHash,
                heParamHash: baseFields.heParamHash,
                setupPackage,
            }),
        ).toThrow(/collective public key coefficient root/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyHash:
                    baseFields.aggregateSelectionPolicyHash,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    randomnessSourceEvidence: {
                        ...bridgeEncryptionEvidence.randomnessSourceEvidence,
                        callerSuppliedDevelopmentRandomness: true,
                    },
                },
                bridgeEvidenceVerification: {
                    ...bridgeEvidenceVerification,
                    randomnessSourceEvidence: {
                        ...bridgeEvidenceVerification.randomnessSourceEvidence,
                        callerSuppliedDevelopmentRandomness: true,
                    },
                },
                bridgeWitnessPrivacyProfileHash:
                    baseFields.bridgeWitnessPrivacyProfileHash,
                heParamHash: baseFields.heParamHash,
                setupPackage,
            }),
        ).toThrow(/randomness source evidence development flag/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyHash:
                    baseFields.aggregateSelectionPolicyHash,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    randomnessSourceEvidence: {
                        ...bridgeEncryptionEvidence.randomnessSourceEvidence,
                        claimBearingEntropyEvidence: true,
                    },
                },
                bridgeEvidenceVerification: {
                    ...bridgeEvidenceVerification,
                    randomnessSourceEvidence: {
                        ...bridgeEvidenceVerification.randomnessSourceEvidence,
                        claimBearingEntropyEvidence: true,
                    },
                },
                bridgeWitnessPrivacyProfileHash:
                    baseFields.bridgeWitnessPrivacyProfileHash,
                heParamHash: baseFields.heParamHash,
                setupPackage,
            }),
        ).toThrow(/randomness source evidence claim-bearing entropy flag/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyHash:
                    baseFields.aggregateSelectionPolicyHash,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    aggregateRelationChallengeHex: '0'.repeat(48),
                },
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileHash:
                    baseFields.bridgeWitnessPrivacyProfileHash,
                heParamHash: baseFields.heParamHash,
                setupPackage,
            }),
        ).toThrow(/aggregate relation challenge summary/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyHash:
                    baseFields.aggregateSelectionPolicyHash,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    aggregateRelationSubproofSizeBytes:
                        aggregateRelationSubproofSizeBytes + 1,
                },
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileHash:
                    baseFields.bridgeWitnessPrivacyProfileHash,
                heParamHash: baseFields.heParamHash,
                setupPackage,
            }),
        ).toThrow(/aggregate relation subproof size/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyHash:
                    baseFields.aggregateSelectionPolicyHash,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    aggregateReducedCoordinateCount:
                        aggregateDerivationComponent.statement
                            .shareVectorWidth - 1,
                },
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileHash:
                    baseFields.bridgeWitnessPrivacyProfileHash,
                heParamHash: baseFields.heParamHash,
                setupPackage,
            }),
        ).toThrow(/aggregate reduced coordinate count/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyHash:
                    baseFields.aggregateSelectionPolicyHash,
                bridgeEncryptionEvidence: {
                    ...bridgeEncryptionEvidence,
                    canonicalBytesHash512: '5'.repeat(128),
                },
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileHash:
                    baseFields.bridgeWitnessPrivacyProfileHash,
                heParamHash: baseFields.heParamHash,
                setupPackage,
            }),
        ).toThrow(/canonical bridge proof statement hash/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyHash: hash(
                    'wrong-aggregate-selection-policy',
                ),
                bridgeEncryptionEvidence,
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileHash:
                    baseFields.bridgeWitnessPrivacyProfileHash,
                heParamHash: baseFields.heParamHash,
                setupPackage,
            }),
        ).toThrow(/canonical bridge proof statement hash/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyHash:
                    baseFields.aggregateSelectionPolicyHash,
                bridgeEncryptionEvidence,
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileHash: hash(
                    'wrong-bridge-witness-privacy',
                ),
                heParamHash: baseFields.heParamHash,
                setupPackage,
            }),
        ).toThrow(/canonical bridge proof statement hash/u);
        expect(() =>
            createPendingBridgeProofRecordFromBridgeEvidence({
                aggregateDerivationComponent,
                aggregateSelectionPolicyHash:
                    baseFields.aggregateSelectionPolicyHash,
                bridgeEncryptionEvidence,
                bridgeEvidenceVerification,
                bridgeWitnessPrivacyProfileHash:
                    baseFields.bridgeWitnessPrivacyProfileHash,
                heParamHash: hash('wrong-he-param'),
                setupPackage,
            }),
        ).toThrow(/canonical bridge proof statement hash/u);
    });

    it('creates proof-checked aggregate contributions from checked bridge proof records', () => {
        const expectedContribution = createAggregateContributionFixture({
            rosterPosition: 1,
        });

        const contribution = createAggregateContributionFromBridgeProofRecord({
            actionContext: expectedContribution.actionContext,
            boardPosition: expectedContribution.boardPosition,
            bridgeProofRecord: expectedContribution.bridgeProofRecord,
            closeRecordHash: expectedContribution.closeRecordHash,
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
        expect(contribution.bridgeProofRecordHash).toBe(
            contribution.bridgeProofRecord.bridgeProofRecordHash,
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
                closeRecordHash: pendingContribution.closeRecordHash,
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
                closeRecordHash: checkedContribution.closeRecordHash,
                signature: checkedContribution.signature,
            }),
        ).toThrow(/action context/u);

        expect(() =>
            createAggregateContributionFromBridgeProofRecord({
                actionContext: {
                    ...checkedContribution.actionContext,
                    actionContextHash: hash('replayed-action-context'),
                    actionSequence:
                        checkedContribution.actionContext.actionSequence + 1,
                    boardSequence:
                        checkedContribution.actionContext.boardSequence + 100,
                },
                boardPosition: checkedContribution.boardPosition,
                bridgeProofRecord: checkedContribution.bridgeProofRecord,
                closeRecordHash: checkedContribution.closeRecordHash,
                signature: checkedContribution.signature,
            }),
        ).toThrow(/action context/u);

        expect(() =>
            createAggregateContributionFromBridgeProofRecord({
                actionContext: checkedContribution.actionContext,
                boardPosition: checkedContribution.boardPosition,
                bridgeProofRecord: checkedContribution.bridgeProofRecord,
                closeRecordHash: 'not-a-hash',
                signature: checkedContribution.signature,
            }),
        ).toThrow(/close-record hash/u);
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
                closeRecordHash: contribution.closeRecordHash,
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
                closeRecordHash: contribution.closeRecordHash,
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
                closeRecordHash: contribution.closeRecordHash,
                signature: {
                    ...contribution.signature,
                    signedRoot: {
                        ...contribution.signature.signedRoot,
                        objectRoot: hash('wrong-contribution-root'),
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
            expectedAggregateSelectionPolicyHash:
                baseFields.aggregateSelectionPolicyHash,
            requiredPostVotingClosedContextHash:
                baseFields.postVotingClosedContextHash,
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
            encryptedAggregateShareCiphertextRoot: hash(
                'changed-share-ciphertext',
            ),
            rosterPosition: 1,
        });
        const staleContribution = {
            ...contribution,
            encryptedAggregateShareCiphertextRoot: hash(
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
        expect(contribution.aggregateContributionHash).not.toBe(
            changedContribution.aggregateContributionHash,
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

            const verification =
                verifyAggregateContributionStructure(leakyContribution);

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

        const verification =
            verifyAggregateContributionStructure(leakyContribution);

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
            expectedAggregateSelectionPolicyHash:
                baseFields.aggregateSelectionPolicyHash,
            requiredPostVotingClosedContextHash:
                baseFields.postVotingClosedContextHash,
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
            expectedAggregateSelectionPolicyHash:
                baseFields.aggregateSelectionPolicyHash,
            requiredPostVotingClosedContextHash:
                baseFields.postVotingClosedContextHash,
        });

        expect(selection.ok).toBe(true);
        expect(
            selection.selectedContributions.map(
                (contribution) => contribution.contributorRosterPosition,
            ),
        ).toEqual([1, 2]);
        expect(selectionWithLateExtra.firstValidOrderHash).toBe(
            selection.firstValidOrderHash,
        );
    });

    it('rejects conflicting duplicate identities, stale recovery epochs, and stale contexts', () => {
        const contribution = createAggregateContributionFixture({
            rosterPosition: 1,
        });
        const duplicateIdentityContribution =
            createAggregateContributionFixture({
                encryptedAggregateShareCiphertextRoot: hash(
                    'duplicate-identity-ciphertext',
                ),
                rosterPosition: 1,
            });
        const staleRecoveryContribution = createAggregateContributionFixture({
            recoveryEpoch: 0,
            rosterPosition: 2,
        });
        const wrongContextContribution = createAggregateContributionFixture({
            contextHash: hash('wrong-post-voting-context'),
            rosterPosition: 3,
        });

        expect(
            selectFirstValidAggregateContributions({
                aggregateContributionQuorum: 1,
                contributions: [contribution, duplicateIdentityContribution],
                currentRecoveryEpochMap: recoveryMapFor([contribution]),
                expectedAggregateSelectionPolicyHash:
                    baseFields.aggregateSelectionPolicyHash,
                requiredPostVotingClosedContextHash:
                    baseFields.postVotingClosedContextHash,
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
                expectedAggregateSelectionPolicyHash:
                    baseFields.aggregateSelectionPolicyHash,
                requiredPostVotingClosedContextHash:
                    baseFields.postVotingClosedContextHash,
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
                expectedAggregateSelectionPolicyHash:
                    baseFields.aggregateSelectionPolicyHash,
                requiredPostVotingClosedContextHash:
                    baseFields.postVotingClosedContextHash,
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
            expectedAggregateSelectionPolicyHash:
                baseFields.aggregateSelectionPolicyHash,
            requiredPostVotingClosedContextHash:
                baseFields.postVotingClosedContextHash,
        });
        const coefficientReport = deriveInterpolationCoefficientReport({
            contributorRosterPositions: [1, 2],
            rosterSize: 20,
            threshold: 2,
        });
        const record = createAggregateReadyRecord({
            aggregateContributionQuorum: 2,
            firstValidOrderHash:
                selection.firstValidOrderHash ?? hash('missing'),
            rosterSize: 20,
            selectedContributions: selection.selectedContributions,
            suppliedInterpolationCoefficientReport: coefficientReport,
        });
        const repeatedRecord = createAggregateReadyRecord({
            aggregateContributionQuorum: 2,
            firstValidOrderHash:
                selection.firstValidOrderHash ?? hash('missing'),
            rosterSize: 20,
            selectedContributions: selection.selectedContributions,
        });
        const changedContribution = createAggregateContributionFixture({
            encryptedAggregateShareCiphertextRoot: hash(
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
            expectedAggregateSelectionPolicyHash:
                baseFields.aggregateSelectionPolicyHash,
            requiredPostVotingClosedContextHash:
                baseFields.postVotingClosedContextHash,
        });
        const changedRecord = createAggregateReadyRecord({
            aggregateContributionQuorum: 2,
            firstValidOrderHash:
                changedSelection.firstValidOrderHash ?? hash('missing'),
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
        expect(record.interpolationCoefficientReportHash).toBe(
            coefficientReport.reportHash,
        );
        expect(record.selectedContributorRosterPositions).toEqual([1, 2]);
        expect(record.aggregateReadyRecordHash).toBe(
            repeatedRecord.aggregateReadyRecordHash,
        );
        expect(changedRecord.aggregateReadyRecordHash).not.toBe(
            record.aggregateReadyRecordHash,
        );
        expect(() =>
            createAggregateReadyRecord({
                aggregateContributionQuorum: 2,
                firstValidOrderHash: hash('forged-first-valid-order'),
                rosterSize: 20,
                selectedContributions: selection.selectedContributions,
            }),
        ).toThrow(/first-valid order hash/u);
        expect(() =>
            createAggregateReadyRecord({
                aggregateContributionQuorum: 2,
                firstValidOrderHash:
                    selection.firstValidOrderHash ?? hash('missing'),
                rosterSize: 20,
                selectedContributions: selection.selectedContributions,
                suppliedInterpolationCoefficientReport: mismatchedReport,
            }),
        ).toThrow(/does not match recomputation/u);

        const {
            aggregateReadyRecordHash: originalAggregateReadyRecordHash,
            ...recordWithoutHash
        } = record;
        void originalAggregateReadyRecordHash;
        const forgedFirstValidOrderHash = hash(
            'forged-verifier-first-valid-order',
        );
        const forgedRecordPayload: Omit<
            AggregateReadyRecord,
            'aggregateReadyRecordHash'
        > = {
            ...recordWithoutHash,
            encryptedAggregateReconstructionRoot:
                deriveEncryptedAggregateReconstructionRoot({
                    aggregateSelectionPolicyHash:
                        record.aggregateSelectionPolicyHash,
                    encryptedAggregateReconstructionHash:
                        record.encryptedAggregateReconstructionHash,
                    encryptedAggregateShareCiphertextRoots:
                        record.encryptedAggregateShareCiphertextRoots,
                    firstValidOrderHash: forgedFirstValidOrderHash,
                    interpolationCoefficientReportHash:
                        record.interpolationCoefficientReportHash,
                    selectedAggregateContributionHashes:
                        record.selectedAggregateContributionHashes,
                }),
            firstValidOrderHash: forgedFirstValidOrderHash,
        };
        const forgedRecord = {
            ...forgedRecordPayload,
            aggregateReadyRecordHash:
                deriveAggregateReadyRecordHash(forgedRecordPayload),
        };

        expect(verifyAggregateReadyRecordStructure(forgedRecord).ok).toBe(
            false,
        );
    });
});
