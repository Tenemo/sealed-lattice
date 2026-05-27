import {
    claimTierForRosterSize,
    lowerHexDigest,
    type ShapeConfigRow,
    type Variant,
} from './shared.js';

import {
    deriveProtocolDigest,
    type ProtocolDigestNamespace,
} from '#packages/crypto/src/index';
import {
    createBallotPrivacyProfileSet,
    deriveBridgeProofProfileDigest,
    deriveBridgeProofStatementDigest,
    deriveBridgeProofTargetContractDigest,
} from '#packages/protocol/src/ballot-privacy/index';
import {
    deriveThresholdProfile,
    deriveThresholdProfileDigest,
} from '#packages/protocol/src/lifecycle/thresholds';
import type { ProtocolDigest } from '#packages/types/src/index';

const bridgeProofProfileId = 'EncryptedAggregateBridge-v1';
const proofBackend = 'SealedLatticeBridgeRelation';
const bgvEncryptionProofSubrelation =
    'SealedLatticeDevelopmentCiphertextEquationRelation';
const maximumRosterSize = 20;
const minimumRosterSize = 3;

type ShapeStatement = {
    readonly ballotSetDigest: ProtocolDigest;
    readonly ceremonyId: string;
    readonly contributorActionContextDigest: ProtocolDigest;
    readonly contributorIdentity: string;
    readonly contributorRosterExternalAcceptanceDigest: ProtocolDigest;
    readonly contributorRosterPosition: number;
    readonly encodedShareVectorLayoutDigest: ProtocolDigest;
    readonly manifestDigest: ProtocolDigest;
    readonly optionCount: number;
    readonly participantCount: number;
    readonly pollSpecDigest: ProtocolDigest;
    readonly postVotingClosedContextDigest: ProtocolDigest;
    readonly rosterDigest: ProtocolDigest;
    readonly rosterExternalAcceptanceDigest: ProtocolDigest;
    readonly shareCommitmentMessageBoundCertDigest: ProtocolDigest;
    readonly shareVectorWidth: number;
    readonly thresholdProfileDigest: ProtocolDigest;
    readonly votingClosedBoardHeadDigest: ProtocolDigest;
};

const syntheticDigest = (
    digestType: ProtocolDigestNamespace,
    label: string,
): ProtocolDigest =>
    deriveProtocolDigest(digestType, {
        label,
        purpose: 'encrypted-aggregate-bridge-shape-config-matrix',
    });

const thresholdDigestForVariant = (variant: Variant): ProtocolDigest => {
    const pollSpecDigest = syntheticDigest(
        'PollSpecDigest',
        `poll-spec-${variant.rosterSize}-${variant.optionCount}`,
    );
    const rosterDigest = syntheticDigest(
        'RosterDigest',
        `roster-${variant.rosterSize}`,
    );
    const thresholdProfile = deriveThresholdProfile({
        casualMicroRosterAcknowledged: variant.rosterSize < 10,
        rosterSize: variant.rosterSize,
    });

    return deriveThresholdProfileDigest({
        maxRosterSize: maximumRosterSize,
        minRosterSize: minimumRosterSize,
        pollSpecDigest,
        rosterDigest,
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
    const rosterDigest = syntheticDigest(
        'RosterDigest',
        `roster-${variant.rosterSize}`,
    );
    const pollSpecDigest = syntheticDigest(
        'PollSpecDigest',
        `poll-spec-${variant.rosterSize}-${variant.optionCount}`,
    );

    return {
        ballotSetDigest: syntheticDigest(
            'BallotSetDigest',
            `ballot-set-${variant.rosterSize}-${variant.optionCount}`,
        ),
        ceremonyId: `shape-config-ceremony-${variant.rosterSize}`,
        contributorActionContextDigest: syntheticDigest(
            'ActionContextDigest',
            `action-context-${variant.rosterSize}-${variant.optionCount}`,
        ),
        contributorIdentity: 'receiver-1',
        contributorRosterExternalAcceptanceDigest: syntheticDigest(
            'RosterExternalAcceptanceDigest',
            `contributor-acceptance-${variant.rosterSize}`,
        ),
        contributorRosterPosition: 1,
        encodedShareVectorLayoutDigest:
            profileSet.encodedShareVectorLayoutProfile
                .encodedShareVectorLayoutDigest,
        manifestDigest: syntheticDigest(
            'ElectionManifestDigest',
            `manifest-${variant.rosterSize}-${variant.optionCount}`,
        ),
        optionCount: variant.optionCount,
        participantCount: variant.rosterSize,
        pollSpecDigest,
        postVotingClosedContextDigest: syntheticDigest(
            'PostVotingClosedContextDigest',
            `post-voting-closed-${variant.rosterSize}-${variant.optionCount}`,
        ),
        rosterDigest,
        rosterExternalAcceptanceDigest: syntheticDigest(
            'RosterExternalAcceptanceDigest',
            `roster-acceptance-${variant.rosterSize}`,
        ),
        shareCommitmentMessageBoundCertDigest: syntheticDigest(
            'ShareCommitmentMessageBoundCertDigest',
            `share-commitment-bound-${variant.optionCount}`,
        ),
        shareVectorWidth,
        thresholdProfileDigest: thresholdDigestForVariant(variant),
        votingClosedBoardHeadDigest: syntheticDigest(
            'BoardHeadDigest',
            `closed-board-head-${variant.rosterSize}-${variant.optionCount}`,
        ),
    };
};

const syntheticBridgeProofStatementDigest = (input: {
    readonly aggregateInputLayoutDigest: ProtocolDigest;
    readonly bridgeProofTargetContractDigest: ProtocolDigest;
    readonly statement: ShapeStatement;
    readonly variant: Variant;
}): ProtocolDigest => {
    const profileSet = createBallotPrivacyProfileSet({
        optionCount: input.variant.optionCount,
    });
    const bridgeProofProfileDigest = deriveBridgeProofProfileDigest({
        bgvEncryptionProofSubrelation,
        bridgeProofProfileId,
        proofBackend,
    });

    return deriveBridgeProofStatementDigest({
        aggregateDerivationComponentDigest: syntheticDigest(
            'AggregateDerivationComponentDigest',
            `component-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        aggregateInputEncodingProfileDigest:
            profileSet.aggregateInputEncodingProfile
                .aggregateInputEncodingProfileDigest,
        aggregateQuotientCoordinateCount: input.statement.shareVectorWidth,
        aggregateReducedCoordinateCount: input.statement.shareVectorWidth,
        aggregateSelectionPolicyDigest: syntheticDigest(
            'AggregateSelectionPolicyDigest',
            `selection-policy-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        aggregateShareCommitmentDigest: syntheticDigest(
            'AggregateShareCommitmentDigest',
            `aggregate-share-commitment-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        aggregateToPlaintextBindingStatus:
            'AggregateToPlaintextBindingProofChecked',
        ballotScoreEncodingProfileDigest:
            profileSet.ballotScoreEncodingProfile
                .ballotScoreEncodingProfileDigest,
        ballotSetDigest: input.statement.ballotSetDigest,
        ballotShareLayoutProfileDigest:
            profileSet.ballotShareLayoutProfile.ballotShareLayoutProfileDigest,
        basisId: 'QData',
        bgvBatchEncoderDigest: syntheticDigest(
            'BGVBatchEncoderDigest',
            'shape-config-batch-encoder',
        ),
        bgvEncryptionProofStatus: 'BgvCiphertextEquationChecked',
        bgvProfileDigest: syntheticDigest(
            'BGVProfileDigest',
            'shape-config-bgv-profile',
        ),
        bgvPublicKeyRoot: syntheticDigest(
            'BGVPublicKeyRoot',
            `bgv-public-key-${input.variant.rosterSize}`,
        ),
        bgvRandomnessBoundProofStatus:
            'BgvRandomnessErrorSupportPolynomialChecked',
        bridgeClaimClosureStatus: 'BridgeProofClaimClosureMissing',
        bridgeLayoutDigest: input.aggregateInputLayoutDigest,
        bridgeProofTargetContractDigest: input.bridgeProofTargetContractDigest,
        bridgeWitnessPrivacyProfileDigest: syntheticDigest(
            'BridgeWitnessPrivacyProfileDigest',
            `witness-privacy-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        canonicalByteLength: 8_388_608,
        canonicalBytesHash512: 'ab'.repeat(64),
        canonicalCiphertextConventionDigest: syntheticDigest(
            'CanonicalCiphertextConventionDigest',
            'shape-config-ciphertext-convention',
        ),
        ceremonyId: input.statement.ceremonyId,
        ciphertextRoot: syntheticDigest(
            'CiphertextRoot',
            `ciphertext-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        coefficientCount: 32_768,
        coefficientDomainCanonical: true,
        collectivePublicKeyRoot: syntheticDigest(
            'CollectivePublicKeyRoot',
            `collective-public-key-${input.variant.rosterSize}`,
        ),
        contributorActionContextDigest:
            input.statement.contributorActionContextDigest,
        contributorIdentity: input.statement.contributorIdentity,
        contributorRosterExternalAcceptanceDigest:
            input.statement.contributorRosterExternalAcceptanceDigest,
        contributorRosterPosition: input.statement.contributorRosterPosition,
        encodedAggregateLayoutDigest:
            profileSet.encodedAggregateLayoutProfile
                .encodedAggregateLayoutDigest,
        encodedShareVectorLayoutDigest:
            input.statement.encodedShareVectorLayoutDigest,
        encryptedAggregateBridgeDigest: syntheticDigest(
            'EncryptedAggregateBridgeDigest',
            `bridge-binding-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        encryptedAggregateInputLayoutDigest: input.aggregateInputLayoutDigest,
        encryptedAggregateInputRoot: syntheticDigest(
            'EncryptedAggregateInputRoot',
            `aggregate-input-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        encryptedAggregateReconstructionDigest: syntheticDigest(
            'EncryptedAggregateReconstructionDigest',
            `reconstruction-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        encryptedAggregateShareCiphertextRoot: syntheticDigest(
            'EncryptedAggregateShareCiphertextRoot',
            `aggregate-input-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        encryptedAggregateTargetBasisDataRoot: syntheticDigest(
            'EncryptedAggregateTargetBasisDataRoot',
            `target-basis-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        heParamDigest: syntheticDigest(
            'HEParamDigest',
            `he-params-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        hwangPiopStatus: 'DeferredUntilSealedLatticeBgvRnsCompatibilityFreeze',
        level: 15,
        manifestDigest: input.statement.manifestDigest,
        optionCount: input.statement.optionCount,
        participantCount: input.statement.participantCount,
        plaintextRoot: syntheticDigest(
            'PlaintextRoot',
            `plaintext-${input.variant.rosterSize}-${input.variant.optionCount}`,
        ),
        pollSpecDigest: input.statement.pollSpecDigest,
        postVotingClosedContextDigest:
            input.statement.postVotingClosedContextDigest,
        proofProfileDigest: bridgeProofProfileDigest,
        rnsCrtConsistencyProofStatus: 'RnsCrtConsistencyRelationChecked',
        rosterDigest: input.statement.rosterDigest,
        rustBgvBackendProfileDigest: syntheticDigest(
            'RustBgvBackendProfileDigest',
            'shape-config-rust-bgv-backend',
        ),
        sampledOnlyBridgeVerificationAccepted: false,
        sampledPublicRelationCheckPolicyDigest: syntheticDigest(
            'BridgeProofRecordDigest',
            'shape-config-sampled-policy',
        ),
        setupPackageDigest: syntheticDigest(
            'BGVPassiveSetupPackageDigest',
            `setup-package-${input.variant.rosterSize}`,
        ),
        shareCommitmentMessageBoundCertDigest:
            input.statement.shareCommitmentMessageBoundCertDigest,
        shareVectorWidth: input.statement.shareVectorWidth,
        sharedWitnessBindingRequired: true,
        sharedWitnessBindingStatus: 'SharedWitnessBindingRelationChecked',
        sharedWitnessChallengeBitsPerCheck: 64,
        sharedWitnessCheckCount: 2,
        sharedWitnessSoundnessBits: 128,
        sharedWitnessZeroKnowledgeStatus:
            'SharedWitnessZeroKnowledgeResponseDistributionChecked',
        slotCount: 32_768,
        thresholdProfileDigest: input.statement.thresholdProfileDigest,
        topKEvaluatorInputLayoutDigest: syntheticDigest(
            'TopKEvaluatorInputLayoutDigest',
            `top-k-layout-${input.variant.optionCount}`,
        ),
        votingClosedBoardHeadDigest:
            input.statement.votingClosedBoardHeadDigest,
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
        const aggregateInputLayoutDigest = deriveProtocolDigest(
            'BridgeLayoutDigest',
            {
                coordinateOrder:
                    'score, score_bucket_1, ..., score_bucket_10 for each option',
                layout: 'AggregatedScalarAndScoreBucketCoordinates',
                optionCount: variant.optionCount,
                purpose:
                    'sealed-lattice-aggregate-bridge-shape-config-layout-v1',
                shareVectorWidth: statement.shareVectorWidth,
            },
        );
        const bridgeProofTargetContractDigest =
            deriveBridgeProofTargetContractDigest({
                aggregateQuotientCoordinateCount: statement.shareVectorWidth,
                aggregateReducedCoordinateCount: statement.shareVectorWidth,
            });
        const bridgeProofStatementDigest = syntheticBridgeProofStatementDigest({
            aggregateInputLayoutDigest,
            bridgeProofTargetContractDigest,
            statement,
            variant,
        });
        const statementDimensionDigest = deriveProtocolDigest(
            'BridgeProofRecordDigest',
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
            aggregateInputLayoutDigest,
            bridgeProofStatementDigest,
            bridgeProofTargetContractDigest,
            claimTier: claimTierForRosterSize(variant.rosterSize),
            failureReason: null,
            optionCount: variant.optionCount,
            rosterSize: variant.rosterSize,
            selectedContributionCount,
            shareVectorWidth: statement.shareVectorWidth,
            statementDimensionDigest,
            status: 'passed',
            thresholdProfileHash: statement.thresholdProfileDigest,
            trusteeAggregateThreshold: thresholdProfile.pvssThreshold,
        };
    } catch (error) {
        const thresholdProfile = deriveThresholdProfile({
            casualMicroRosterAcknowledged: variant.rosterSize < 10,
            rosterSize: variant.rosterSize,
        });

        return {
            aggregateInputLayoutDigest: lowerHexDigest(
                `shape-config-layout-failed-${variant.rosterSize}-${variant.optionCount}`,
            ),
            bridgeProofStatementDigest: lowerHexDigest(
                `shape-config-statement-failed-${variant.rosterSize}-${variant.optionCount}`,
            ),
            bridgeProofTargetContractDigest: lowerHexDigest(
                `shape-config-target-contract-failed-${variant.rosterSize}-${variant.optionCount}`,
            ),
            claimTier: claimTierForRosterSize(variant.rosterSize),
            failureReason:
                error instanceof Error ? error.message : String(error),
            optionCount: variant.optionCount,
            rosterSize: variant.rosterSize,
            selectedContributionCount: thresholdProfile.pvssThreshold,
            shareVectorWidth: variant.optionCount * 11,
            statementDimensionDigest: lowerHexDigest(
                `shape-config-dimensions-failed-${variant.rosterSize}-${variant.optionCount}`,
            ),
            status: 'failed',
            thresholdProfileHash: lowerHexDigest(
                `shape-config-threshold-failed-${variant.rosterSize}-${variant.optionCount}`,
            ),
            trusteeAggregateThreshold: thresholdProfile.pvssThreshold,
        };
    }
};

export const buildShapeConfigRows = (
    variants: readonly Variant[],
): readonly ShapeConfigRow[] => variants.map(buildShapeConfigRow);
