import {
    claimTierForRosterSize,
    lowerHexHash,
    type ShapeConfigRow,
    type Variant,
} from './shared.js';

import {
    deriveProtocolHash,
    type ProtocolHashNamespace,
} from '#packages/crypto/src/index';
import {
    createBallotPrivacyProfileSet,
    deriveBridgeProofChallengeContextHash,
    deriveBridgeProofProfileHash,
    deriveBridgeProofStatementHash,
    deriveBridgeProofTargetContractHash,
} from '#packages/protocol/src/ballot-privacy/index';
import {
    deriveThresholdProfile,
    deriveThresholdProfileHash,
} from '#packages/protocol/src/lifecycle/thresholds';
import type { ProtocolHash } from '#packages/types/src/index';

const bridgeProofProfileId = 'EncryptedAggregateBridge-v1';
const proofBackend = 'SealedLatticeBridgeRelation';
const bgvEncryptionProofSubrelation =
    'SealedLatticePassiveCollectiveCiphertextEquationRelation';
const bgvEncryptionKeyMaterialKind =
    'passive-transcript-derived-collective-public-key';
const maximumRosterSize = 20;
const minimumRosterSize = 3;

type ShapeStatement = {
    readonly ballotSetHash: ProtocolHash;
    readonly ceremonyId: string;
    readonly contributorActionContextHash: ProtocolHash;
    readonly contributorIdentity: string;
    readonly contributorRosterExternalAcceptanceHash: ProtocolHash;
    readonly contributorRosterPosition: number;
    readonly encodedShareVectorLayoutHash: ProtocolHash;
    readonly manifestHash: ProtocolHash;
    readonly optionCount: number;
    readonly participantCount: number;
    readonly pollSpecHash: ProtocolHash;
    readonly postVotingClosedContextHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly rosterExternalAcceptanceHash: ProtocolHash;
    readonly shareCommitmentMessageBoundCertHash: ProtocolHash;
    readonly shareVectorWidth: number;
    readonly thresholdProfileHash: ProtocolHash;
    readonly votingClosedBoardHeadHash: ProtocolHash;
};

const syntheticHash = (
    hashType: ProtocolHashNamespace,
    label: string,
): ProtocolHash =>
    deriveProtocolHash(hashType, {
        label,
        purpose: 'encrypted-aggregate-bridge-shape-config-matrix',
    });

const syntheticSupportHash = (purpose: string, label: string): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        label,
        purpose,
    });

const thresholdHashForVariant = (variant: Variant): ProtocolHash => {
    const pollSpecHash = syntheticHash(
        'PollSpecHash',
        `poll-spec-${variant.rosterSize}-${variant.optionCount}`,
    );
    const rosterHash = syntheticHash(
        'RosterHash',
        `roster-${variant.rosterSize}`,
    );
    const thresholdProfile = deriveThresholdProfile({
        casualMicroRosterAcknowledged: variant.rosterSize < 10,
        rosterSize: variant.rosterSize,
    });

    return deriveThresholdProfileHash({
        maxRosterSize: maximumRosterSize,
        minRosterSize: minimumRosterSize,
        pollSpecHash,
        rosterHash,
        rosterPolicy: 'OpenLinkPublicRoster',
        smallRosterPolicy:
            variant.rosterSize < 10 ? 'AllowMicroRoster' : 'ForbidMicroRoster',
        thresholdProfile,
        thresholdProfileFamily: 'BalancedDefault',
    });
};

const shapeStatementForVariant = (variant: Variant): ShapeStatement => {
    const profileSet = createBallotPrivacyProfileSet({
        optionCount: variant.optionCount,
    });
    const shareVectorWidth = variant.optionCount * 11;
    const rosterHash = syntheticHash(
        'RosterHash',
        `roster-${variant.rosterSize}`,
    );
    const pollSpecHash = syntheticHash(
        'PollSpecHash',
        `poll-spec-${variant.rosterSize}-${variant.optionCount}`,
    );

    return {
        ballotSetHash: syntheticHash(
            'BallotSetHash',
            `ballot-set-${variant.rosterSize}-${variant.optionCount}`,
        ),
        ceremonyId: `shape-config-ceremony-${variant.rosterSize}`,
        contributorActionContextHash: syntheticHash(
            'ActionContextHash',
            `action-context-${variant.rosterSize}-${variant.optionCount}`,
        ),
        contributorIdentity: 'receiver-1',
        contributorRosterExternalAcceptanceHash: syntheticHash(
            'RosterExternalAcceptanceHash',
            `contributor-acceptance-${variant.rosterSize}`,
        ),
        contributorRosterPosition: 1,
        encodedShareVectorLayoutHash:
            profileSet.encodedShareVectorLayoutProfile
                .encodedShareVectorLayoutHash,
        manifestHash: syntheticHash(
            'ElectionManifestHash',
            `manifest-${variant.rosterSize}-${variant.optionCount}`,
        ),
        optionCount: variant.optionCount,
        participantCount: variant.rosterSize,
        pollSpecHash,
        postVotingClosedContextHash: syntheticHash(
            'PostVotingClosedContextHash',
            `post-voting-closed-${variant.rosterSize}-${variant.optionCount}`,
        ),
        rosterHash,
        rosterExternalAcceptanceHash: syntheticHash(
            'RosterExternalAcceptanceHash',
            `roster-acceptance-${variant.rosterSize}`,
        ),
        shareCommitmentMessageBoundCertHash: syntheticHash(
            'ShareCommitmentMessageBoundCertHash',
            `share-commitment-bound-${variant.optionCount}`,
        ),
        shareVectorWidth,
        thresholdProfileHash: thresholdHashForVariant(variant),
        votingClosedBoardHeadHash: syntheticHash(
            'BoardHeadHash',
            `closed-board-head-${variant.rosterSize}-${variant.optionCount}`,
        ),
    };
};

const syntheticBridgeProofStatementHash = (input: {
    readonly aggregateInputLayoutHash: ProtocolHash;
    readonly bridgeProofTargetContractHash: ProtocolHash;
    readonly statement: ShapeStatement;
    readonly variant: Variant;
}): ProtocolHash => {
    const profileSet = createBallotPrivacyProfileSet({
        optionCount: input.variant.optionCount,
    });
    const bridgeProofProfileHash = deriveBridgeProofProfileHash({
        bgvEncryptionKeyMaterialKind,
        bgvEncryptionProofSubrelation,
        bridgeProofProfileId,
        claimBearingBridgeEncryption: false,
        developmentKeyOnly: false,
        proofBackend,
        thresholdDecryptable: true,
    });

    return deriveBridgeProofStatementHash({
        aggregateDerivationComponentHash: syntheticHash(
            'AggregateDerivationComponentHash',
            `component-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        aggregateInputEncodingProfileHash:
            profileSet.aggregateInputEncodingProfile
                .aggregateInputEncodingProfileHash,
        aggregateQuotientCoordinateCount: input.statement.shareVectorWidth,
        aggregateReducedCoordinateCount: input.statement.shareVectorWidth,
        aggregateSelectionPolicyHash: syntheticHash(
            'ChallengeDomainHash',
            `selection-policy-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        aggregateShareCommitmentHash: syntheticHash(
            'AggregateShareCommitmentHash',
            `aggregate-share-commitment-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        aggregateToPlaintextBindingStatus:
            'AggregateToPlaintextModularBindingChecked',
        ballotScoreEncodingProfileHash:
            profileSet.ballotScoreEncodingProfile
                .ballotScoreEncodingProfileHash,
        ballotSetHash: input.statement.ballotSetHash,
        ballotShareLayoutProfileHash:
            profileSet.ballotShareLayoutProfile.ballotShareLayoutProfileHash,
        basisId: 'QData',
        batchEncodingBoundCertificateHash: syntheticHash(
            'BridgeProofRecordHash',
            `batch-lift-bound-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        bgvBatchEncoderHash: syntheticHash(
            'BGVBatchEncoderHash',
            'shape-config-batch-encoder',
        ),
        bgvEncryptionKeyMaterialKind,
        bgvEncryptionProofStatus: 'BgvCiphertextEquationChecked',
        bgvProfileHash: syntheticHash(
            'BGVProfileHash',
            'shape-config-bgv-profile',
        ),
        bgvPublicKeyRoot: syntheticHash(
            'BGVPublicKeyRoot',
            `bgv-public-key-${input.variant.rosterSize}`,
        ),
        bgvRandomnessBoundProofStatus:
            'BgvRandomnessErrorSupportPolynomialChecked',
        bridgeClaimClosureStatus: 'BridgeProofClaimClosureMissing',
        bridgeLayoutHash: input.aggregateInputLayoutHash,
        bridgeProofTargetContractHash: input.bridgeProofTargetContractHash,
        bridgeWitnessPrivacyProfileHash: syntheticSupportHash(
            'encrypted-aggregate-bridge-shape-config-witness-privacy-v1',
            `witness-privacy-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        canonicalByteLength: 8_388_608,
        canonicalBytesHash512: 'ab'.repeat(64),
        canonicalCiphertextConventionHash: syntheticHash(
            'CanonicalCiphertextConventionHash',
            'shape-config-ciphertext-convention',
        ),
        ceremonyId: input.statement.ceremonyId,
        ciphertextRoot: syntheticHash(
            'CiphertextRoot',
            `ciphertext-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        claimBearingBridgeEncryption: false,
        coefficientCount: 32_768,
        coefficientDomainCanonical: true,
        collectivePublicKeyRoot: syntheticHash(
            'CollectivePublicKeyRoot',
            `collective-public-key-${input.variant.rosterSize}`,
        ),
        collectivePublicKeyCoefficientRoot: syntheticHash(
            'CollectivePublicKeyRoot',
            `collective-public-key-coefficients-${input.variant.rosterSize}`,
        ),
        contributorActionContextHash:
            input.statement.contributorActionContextHash,
        contributorIdentity: input.statement.contributorIdentity,
        contributorRosterExternalAcceptanceHash:
            input.statement.contributorRosterExternalAcceptanceHash,
        contributorRosterPosition: input.statement.contributorRosterPosition,
        developmentKeyOnly: false,
        encodedAggregateLayoutHash:
            profileSet.encodedAggregateLayoutProfile.encodedAggregateLayoutHash,
        encodedShareVectorLayoutHash:
            input.statement.encodedShareVectorLayoutHash,
        encryptedAggregateBridgeHash: syntheticHash(
            'EncryptedAggregateBridgeHash',
            `bridge-binding-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        encryptedAggregateInputLayoutHash: input.aggregateInputLayoutHash,
        encryptedAggregateInputRoot: syntheticHash(
            'ChallengeDomainHash',
            `aggregate-input-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        encryptedAggregateReconstructionHash: syntheticHash(
            'EncryptedAggregateReconstructionHash',
            `reconstruction-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        encryptedAggregateShareCiphertextRoot: syntheticHash(
            'EncryptedAggregateShareCiphertextRoot',
            `aggregate-input-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        encryptedAggregateTargetBasisRoot: syntheticHash(
            'EncryptedAggregateTargetBasisRoot',
            `target-basis-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        heParamHash: syntheticSupportHash(
            'encrypted-aggregate-bridge-shape-config-he-param-v1',
            `he-params-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        hwangPiopStatus: 'DeferredUntilSealedLatticeBgvRnsProfileFreeze',
        level: 15,
        manifestHash: input.statement.manifestHash,
        aggregateDerivationVerificationScope:
            'AggregateDerivationFullVerificationPreconditionNotBound',
        plaintextCanonicalLiftProofStatus: 'PlaintextCanonicalLiftProofChecked',
        plaintextCoefficientBindingCommitmentHash: syntheticHash(
            'BridgeProofRecordHash',
            `plaintext-binding-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        plaintextEncodingBoundCertificateHash: syntheticHash(
            'BridgeProofRecordHash',
            `batch-lift-bound-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        plaintextEncodingProofModuli: [
            140_737_487_306_753, 140_737_486_716_929,
        ],
        plaintextEncodingProofModulusProduct: '19807040250408114080301121537',
        plaintextEncodingProofModulusProductBitsFloor: 93,
        optionCount: input.statement.optionCount,
        participantCount: input.statement.participantCount,
        plaintextRoot: syntheticHash(
            'PlaintextRoot',
            `plaintext-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        pollSpecHash: input.statement.pollSpecHash,
        postVotingClosedContextHash:
            input.statement.postVotingClosedContextHash,
        proofFriendlyPlaintextBindingStatus:
            'ProofFriendlyPlaintextCoefficientBindingRelationChecked',
        proofFriendlyPlaintextLiftBindingHash: syntheticHash(
            'BridgeProofRecordHash',
            `plaintext-lift-binding-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        proofFriendlyPlaintextLiftBindingStatus:
            'ProofFriendlyPlaintextCoefficientLiftBindingChecked',
        proofProfileHash: bridgeProofProfileHash,
        rnsCrtConsistencyProofStatus: 'RnsCrtConsistencyRelationChecked',
        rosterHash: input.statement.rosterHash,
        rustBgvBackendProfileHash: syntheticHash(
            'RustBgvBackendProfileHash',
            'shape-config-rust-bgv-backend',
        ),
        sampledOnlyBridgeVerificationAccepted: false,
        sampledPublicRelationCheckPolicyHash: syntheticHash(
            'BridgeProofRecordHash',
            'shape-config-sampled-policy',
        ),
        setupPackageHash: syntheticHash(
            'BGVPassiveSetupPackageHash',
            `setup-package-${input.variant.rosterSize}`,
        ),
        shareCommitmentMessageBoundCertHash:
            input.statement.shareCommitmentMessageBoundCertHash,
        shareVectorWidth: input.statement.shareVectorWidth,
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
        batchIntegerLiftProofModuli: [140_737_487_306_753, 140_737_486_716_929],
        batchIntegerLiftProofModulusProduct: '19807040250408114080301121537',
        batchIntegerLiftProofModulusProductBitsFloor: 93,
        sharedWitnessZeroKnowledgeStatus:
            'SharedWitnessZeroKnowledgeResponseDistributionChecked',
        slotCount: 32_768,
        thresholdProfileHash: input.statement.thresholdProfileHash,
        thresholdDecryptable: true,
        topKEvaluatorInputLayoutHash: syntheticHash(
            'TopKEvaluatorInputLayoutHash',
            `top-k-layout-${input.variant.optionCount}`,
        ),
        votingClosedBoardHeadHash: input.statement.votingClosedBoardHeadHash,
    });
};

const assertShapeConfig = (input: {
    readonly selectedContributionCount: number;
    readonly statement: ShapeStatement;
    readonly trusteeAggregateThreshold: number;
    readonly variant: Variant;
}): void => {
    const expectedShareVectorWidth = input.variant.optionCount * 11;
    const shapeChecks: readonly [boolean, string][] = [
        [
            input.statement.participantCount === input.variant.rosterSize,
            'participantCount must derive from roster size',
        ],
        [
            input.statement.optionCount === input.variant.optionCount,
            'optionCount must derive from option count',
        ],
        [
            input.statement.shareVectorWidth === expectedShareVectorWidth,
            'shareVectorWidth must equal 11 * optionCount',
        ],
        [
            input.selectedContributionCount === input.trusteeAggregateThreshold,
            'selected contribution count must equal the derived PVSS threshold',
        ],
        [
            input.variant.rosterSize === input.variant.optionCount ||
                input.statement.participantCount !==
                    input.statement.optionCount,
            'participantCount must not be derived from optionCount',
        ],
        [
            input.statement.shareVectorWidth !== 220 ||
                input.variant.optionCount === 20,
            'shareVectorWidth may be 220 only for m=20 rows',
        ],
        [
            input.statement.participantCount !== 20 ||
                input.variant.rosterSize === 20,
            'participantCount may be 20 only for n=20 rows',
        ],
        [
            input.selectedContributionCount === input.trusteeAggregateThreshold,
            'threshold-shaped selected count must be profile-derived even when the value is 7',
        ],
    ];
    const failedCheck = shapeChecks.find(([passed]) => !passed);
    if (failedCheck !== undefined) {
        throw new Error(failedCheck[1]);
    }
};

export const buildShapeConfigRow = (variant: Variant): ShapeConfigRow => {
    try {
        const thresholdProfile = deriveThresholdProfile({
            casualMicroRosterAcknowledged: variant.rosterSize < 10,
            rosterSize: variant.rosterSize,
        });
        const statement = shapeStatementForVariant(variant);
        const selectedContributionCount = thresholdProfile.pvssThreshold;
        assertShapeConfig({
            selectedContributionCount,
            statement,
            trusteeAggregateThreshold: thresholdProfile.pvssThreshold,
            variant,
        });
        const aggregateInputLayoutHash = deriveProtocolHash(
            'ChallengeDomainHash',
            {
                coordinateOrder:
                    'score, score_bucket_1, ..., score_bucket_10 for each option',
                layout: 'AggregatedScalarAndScoreBucketCoordinates',
                optionCount: variant.optionCount,
                purpose: 'aggregate-bridge-shape-config-layout-v1',
                shareVectorWidth: statement.shareVectorWidth,
            },
        );
        const bridgeProofTargetContractHash =
            deriveBridgeProofTargetContractHash({
                aggregateQuotientCoordinateCount: statement.shareVectorWidth,
                aggregateReducedCoordinateCount: statement.shareVectorWidth,
                aggregateDerivationVerificationScope:
                    'AggregateDerivationFullVerificationPreconditionNotBound',
                bridgeClaimClosureStatus: 'BridgeProofClaimClosureMissing',
                claimBearingBridgeEncryption: false,
            });
        const bridgeProofStatementHash = syntheticBridgeProofStatementHash({
            aggregateInputLayoutHash,
            bridgeProofTargetContractHash,
            statement,
            variant,
        });
        const bridgeProofProfileHash = deriveBridgeProofProfileHash({
            bgvEncryptionKeyMaterialKind,
            bgvEncryptionProofSubrelation,
            bridgeProofProfileId,
            claimBearingBridgeEncryption: false,
            developmentKeyOnly: false,
            proofBackend,
            thresholdDecryptable: true,
        });
        const bridgeProofChallengeContextHash =
            deriveBridgeProofChallengeContextHash({
                bridgeProofProfileHash,
                bridgeProofStatementHash,
                bridgeProofTargetContractHash,
            });
        const statementDimensionHash = deriveProtocolHash(
            'BridgeProofRecordHash',
            {
                aggregateQuotientCoordinateCount: statement.shareVectorWidth,
                aggregateReducedCoordinateCount: statement.shareVectorWidth,
                optionCount: statement.optionCount,
                participantCount: statement.participantCount,
                purpose:
                    'sealed-lattice-aggregate-bridge-shape-config-statement-dimensions-v1',
                selectedContributionCount,
                shareVectorWidth: statement.shareVectorWidth,
                trusteeAggregateThreshold: thresholdProfile.pvssThreshold,
            },
        );

        return {
            aggregateInputLayoutHash,
            bridgeProofChallengeContextHash,
            bridgeProofStatementHash,
            bridgeProofTargetContractHash,
            claimTier: claimTierForRosterSize(variant.rosterSize),
            failureReason: null,
            optionCount: variant.optionCount,
            rosterSize: variant.rosterSize,
            selectedContributionCount,
            shareVectorWidth: statement.shareVectorWidth,
            statementDimensionHash,
            status: 'passed',
            thresholdProfileHash: statement.thresholdProfileHash,
            trusteeAggregateThreshold: thresholdProfile.pvssThreshold,
        };
    } catch (error) {
        const thresholdProfile = deriveThresholdProfile({
            casualMicroRosterAcknowledged: variant.rosterSize < 10,
            rosterSize: variant.rosterSize,
        });

        return {
            aggregateInputLayoutHash: lowerHexHash(
                `shape-config-layout-failed-${variant.rosterSize}-${variant.optionCount}`,
            ),
            bridgeProofStatementHash: lowerHexHash(
                `shape-config-statement-failed-${variant.rosterSize}-${variant.optionCount}`,
            ),
            bridgeProofChallengeContextHash: lowerHexHash(
                `shape-config-challenge-context-failed-${variant.rosterSize}-${variant.optionCount}`,
            ),
            bridgeProofTargetContractHash: lowerHexHash(
                `shape-config-target-contract-failed-${variant.rosterSize}-${variant.optionCount}`,
            ),
            claimTier: claimTierForRosterSize(variant.rosterSize),
            failureReason:
                error instanceof Error ? error.message : String(error),
            optionCount: variant.optionCount,
            rosterSize: variant.rosterSize,
            selectedContributionCount: thresholdProfile.pvssThreshold,
            shareVectorWidth: variant.optionCount * 11,
            statementDimensionHash: lowerHexHash(
                `shape-config-dimensions-failed-${variant.rosterSize}-${variant.optionCount}`,
            ),
            status: 'failed',
            thresholdProfileHash: lowerHexHash(
                `shape-config-threshold-failed-${variant.rosterSize}-${variant.optionCount}`,
            ),
            trusteeAggregateThreshold: thresholdProfile.pvssThreshold,
        };
    }
};

export const buildShapeConfigRows = (
    variants: readonly Variant[],
): readonly ShapeConfigRow[] => variants.map(buildShapeConfigRow);
