import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import {
    aggregateInputEncodingProfileId,
    ballotProofProfileId,
    ballotScoreEncodingProfileId,
    ballotShareLayoutProfileId,
    encodedAggregateLayoutProfileId,
    encodedShareVectorLayoutProfileId,
    fieldEncodingProfileId,
    receiverEncryptionProfileId,
    scoreMembershipProfileId,
    shareCommitmentMessageBoundProfileId,
    shareCommitmentProfileId,
    type AggregateInputEncodingProfile,
    type BallotScoreEncodingProfile,
    type BallotShareLayoutProfile,
    type BallotPrivacyProfileDigests,
    type BallotPrivacyProfileSet,
    type BallotProofProfile,
    type EncodedAggregateLayoutProfile,
    type EncodedShareVectorLayoutProfile,
    type ProtocolDigest,
    type ReceiverEncryptionProfile,
    type RefusalRecord,
    type ScoreMembershipProfile,
    type ShareCommitmentMessageBoundCert,
    type ShareCommitmentMessageBoundCertVerification,
    type ShareCommitmentProfile,
} from '@sealed-lattice/types';

import {
    createRefusal,
    isNonNegativeInteger,
} from '../common/verification-helpers.js';
import { fieldModulus } from '../plaintext-oracle/field.js';

import {
    ballotPrivacyMaximumCertificateGatedTurnout as maximumCertificateGatedTurnout,
    ballotPrivacyMaximumCanonicalFieldElement as maximumCanonicalFieldElement,
    ballotPrivacyMaximumFieldElementBitLength as maximumFieldElementBitLength,
    ballotPrivacyEncodedCoordinatesPerOption,
    ballotPrivacyMaximumOptionCount,
    ballotPrivacyMinimumOptionCount,
    ballotPrivacyMinimumSupportedTurnout as minimumSupportedTurnout,
    ballotPrivacyScoreBucketCount,
    certificateGatedProfileProofSizeTargetBytes,
    getBallotPrivacyEncodedShareVectorWidth,
    mandatoryProfileProofSizeTargetBytes,
    receiverEncryptionCiphertextModulus,
    shareCommitmentMessageBound as commitmentMessageBound,
    shareCommitmentModulusDecimal as shareCommitmentModulus,
    shareCommitmentOpeningInfinityNormBound as openingRandomnessInfinityNormBound,
    shareCommitmentOpeningRandomnessRangeWidth as openingRandomnessRangeWidth,
    shareCommitmentOpeningRandomnessSamplerDomain as openingRandomnessSamplerDomain,
} from './protocol-parameters.js';

const decimalIntegerPattern = /^(0|[1-9][0-9]*)$/u;

type ReceiverEncryptionProfilePayload = Omit<
    ReceiverEncryptionProfile,
    'receiverEncryptionProfileDigest'
>;
type ShareCommitmentProfilePayload = Omit<
    ShareCommitmentProfile,
    'shareCommitmentProfileDigest'
>;
type ScoreMembershipProfilePayload = Omit<
    ScoreMembershipProfile,
    'scoreMembershipProfileDigest'
>;
type BallotScoreEncodingProfilePayload = Omit<
    BallotScoreEncodingProfile,
    'ballotScoreEncodingProfileDigest'
>;
type BallotShareLayoutProfilePayload = Omit<
    BallotShareLayoutProfile,
    'ballotShareLayoutProfileDigest'
>;
type AggregateInputEncodingProfilePayload = Omit<
    AggregateInputEncodingProfile,
    'aggregateInputEncodingProfileDigest'
>;
type EncodedShareVectorLayoutProfilePayload = Omit<
    EncodedShareVectorLayoutProfile,
    'encodedShareVectorLayoutDigest'
>;
type EncodedAggregateLayoutProfilePayload = Omit<
    EncodedAggregateLayoutProfile,
    'encodedAggregateLayoutDigest'
>;

type BallotPrivacyProfileSetInput = {
    readonly optionCount?: number;
};

const defaultProfileOptionCount = ballotPrivacyMaximumOptionCount;

const normalizeProfileOptionCount = (optionCount: number): number => {
    if (
        !Number.isSafeInteger(optionCount) ||
        optionCount < ballotPrivacyMinimumOptionCount ||
        optionCount > ballotPrivacyMaximumOptionCount
    ) {
        throw new RangeError(
            'Ballot privacy profiles require two to twenty options.',
        );
    }

    return optionCount;
};
type BallotProofProfilePayload = Omit<
    BallotProofProfile,
    'ballotProofProfileDigest'
>;
type ShareCommitmentMessageBoundCertPayload = Omit<
    ShareCommitmentMessageBoundCert,
    'shareCommitmentMessageBoundCertDigest'
>;

const compareDecimalIntegerStrings = (left: string, right: string): number => {
    if (
        !decimalIntegerPattern.test(left) ||
        !decimalIntegerPattern.test(right)
    ) {
        throw new RangeError(
            'Decimal integer strings must be canonical non-negative integers.',
        );
    }

    const leftValue = BigInt(left);
    const rightValue = BigInt(right);

    if (leftValue < rightValue) {
        return -1;
    }
    if (leftValue > rightValue) {
        return 1;
    }

    return 0;
};

const deriveReceiverEncryptionProfileDigest = (
    profile: ReceiverEncryptionProfilePayload,
): ProtocolDigest =>
    deriveProtocolDigest('ReceiverEncryptionProfileDigest', profile);

const deriveShareCommitmentProfileDigest = (
    profile: ShareCommitmentProfilePayload,
): ProtocolDigest =>
    deriveProtocolDigest('ShareCommitmentProfileDigest', profile);

const deriveScoreMembershipProfileDigest = (
    profile: ScoreMembershipProfilePayload,
): ProtocolDigest =>
    deriveProtocolDigest('ScoreMembershipProfileDigest', profile);

const deriveBallotScoreEncodingProfileDigest = (
    profile: BallotScoreEncodingProfilePayload,
): ProtocolDigest =>
    deriveProtocolDigest('BallotScoreEncodingProfileDigest', profile);

const deriveBallotShareLayoutProfileDigest = (
    profile: BallotShareLayoutProfilePayload,
): ProtocolDigest =>
    deriveProtocolDigest('BallotShareLayoutProfileDigest', profile);

const deriveAggregateInputEncodingProfileDigest = (
    profile: AggregateInputEncodingProfilePayload,
): ProtocolDigest =>
    deriveProtocolDigest('AggregateInputEncodingProfileDigest', profile);

const deriveEncodedShareVectorLayoutDigest = (
    profile: EncodedShareVectorLayoutProfilePayload,
): ProtocolDigest =>
    deriveProtocolDigest('EncodedShareVectorLayoutDigest', profile);

const deriveEncodedAggregateLayoutDigest = (
    profile: EncodedAggregateLayoutProfilePayload,
): ProtocolDigest =>
    deriveProtocolDigest('EncodedAggregateLayoutDigest', profile);

const deriveBallotProofProfileDigest = (
    profile: BallotProofProfilePayload,
): ProtocolDigest => deriveProtocolDigest('BallotProofProfileDigest', profile);

export const deriveShareCommitmentMessageBoundCertDigest = (
    certificate: ShareCommitmentMessageBoundCertPayload,
): ProtocolDigest =>
    deriveProtocolDigest('ShareCommitmentMessageBoundCertDigest', certificate);

const createReceiverEncryptionProfile = (): ReceiverEncryptionProfile => {
    const profilePayload: ReceiverEncryptionProfilePayload = {
        objectType: 'ReceiverEncryptionProfile',
        objectVersion: 1,
        profileId: receiverEncryptionProfileId,
        scheme: 'LinearModuleLweRegev',
        hardnessAssumption: 'Module-LWE',
        ring: 'Z_q[X]/(X^256 + 1)',
        moduleRank: 4,
        moduleDegree: 256,
        ciphertextModulus: receiverEncryptionCiphertextModulus,
        plaintextModulus: 2,
        fieldElementBitLength: maximumFieldElementBitLength,
        messageEncoding: 'BitSlicedCanonicalGF65537LittleEndian',
        publicMatrixDerivationDomain:
            'sealed.vote/v1/receiver-encryption/public-matrix',
        secretDistribution: 'CenteredBinomialEta2',
        errorDistribution: 'CenteredBinomialEta2',
        encryptionRandomnessDistribution: 'CenteredBinomialEta2',
        parameterSecurityEvidenceStatus: 'ParameterCertificateMissing',
        claimBoundary: 'ReceiverEncryptionParameterSecurityNotClosed',
        payloadBinding: {
            encryptsReceiverShareVector: true,
            encryptsShareCommitmentOpening: true,
            bindsReceiverIdentity: true,
            bindsReceiverRosterPosition: true,
            bindsManifestDigest: true,
            bindsRosterDigest: true,
            bindsPollSpecDigest: true,
            bindsVoterIdentityDigest: true,
            bindsActionContextDigest: true,
        },
        decryptionFailureTarget: '2^-128',
    };

    return {
        ...profilePayload,
        receiverEncryptionProfileDigest:
            deriveReceiverEncryptionProfileDigest(profilePayload),
    };
};

const createShareCommitmentProfile = (
    shareVectorWidth: number,
): ShareCommitmentProfile => {
    const profilePayload: ShareCommitmentProfilePayload = {
        objectType: 'ShareCommitmentProfile',
        objectVersion: 1,
        profileId: shareCommitmentProfileId,
        scheme: 'AdditiveModuleSisCommitment',
        hardnessAssumption: 'Module-SIS',
        commitmentModulus: shareCommitmentModulus,
        moduleRank: 4,
        moduleDegree: 256,
        shareVectorWidth,
        messageFieldModulus: fieldModulus,
        messageRepresentativeMinimum: 0,
        messageRepresentativeMaximum: maximumCanonicalFieldElement,
        messageEncoding: 'CanonicalGF65537RepresentativeVector',
        commitmentFormula:
            'A_message * EncodeShareVector(S) + A_randomness * rho mod q_commit',
        matrixDerivationDomain:
            'sealed.vote/v1/share-commitment/public-matrices',
        openingRandomnessDimension: 64,
        openingRandomnessDistribution: 'UniformCenteredInteger',
        openingRandomnessInfinityNormBound,
        openingRandomnessRangeWidth,
        openingRandomnessSampler: 'RejectionSampledLittleEndianUint16',
        openingRandomnessSamplerDomain,
        openingRandomnessSamplerWordBits: 16,
        aggregateOpeningRandomnessMaximumTurnout:
            maximumCertificateGatedTurnout,
    };

    return {
        ...profilePayload,
        shareCommitmentProfileDigest:
            deriveShareCommitmentProfileDigest(profilePayload),
    };
};

const createScoreMembershipProfile = (): ScoreMembershipProfile => {
    const profilePayload: ScoreMembershipProfilePayload = {
        objectType: 'ScoreMembershipProfile',
        objectVersion: 1,
        profileId: scoreMembershipProfileId,
        relation: 'OneHotScoreMembership',
        scoreMinimum: 1,
        scoreMaximum: 10,
        oneHotWidth: 10,
        constraints: [
            'sum(one_hot_score[1..10]) = 1',
            'score = sum(score_value * one_hot_score[score_value])',
            'one_hot_score entries are boolean',
        ],
    };

    return {
        ...profilePayload,
        scoreMembershipProfileDigest:
            deriveScoreMembershipProfileDigest(profilePayload),
    };
};

const createBallotScoreEncodingProfile = (): BallotScoreEncodingProfile => {
    const profilePayload: BallotScoreEncodingProfilePayload = {
        objectType: 'BallotScoreEncodingProfile',
        objectVersion: 1,
        profileId: ballotScoreEncodingProfileId,
        encoding: 'ScalarScorePlusOneHotScoreBuckets',
        scoreMinimum: 1,
        scoreMaximum: 10,
        oneHotWidth: ballotPrivacyScoreBucketCount,
        coordinatesPerOption: ballotPrivacyEncodedCoordinatesPerOption,
        scalarCoordinateOffset: 0,
        scoreBucketCoordinateOffsets: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        scalarConsistencyConstraint:
            'scalar_score = sum(score_value * one_hot_score[score_value])',
        oneHotConstraint:
            'sum(one_hot_score[1..10]) = 1 and entries are boolean',
    };

    return {
        ...profilePayload,
        ballotScoreEncodingProfileDigest:
            deriveBallotScoreEncodingProfileDigest(profilePayload),
    };
};

const createBallotShareLayoutProfile = (
    shareVectorWidth: number,
): BallotShareLayoutProfile => {
    const profilePayload: BallotShareLayoutProfilePayload = {
        objectType: 'BallotShareLayoutProfile',
        objectVersion: 1,
        profileId: ballotShareLayoutProfileId,
        layout: 'ScalarThenOneHotBucketsPerOption',
        coordinatesPerOption: ballotPrivacyEncodedCoordinatesPerOption,
        minimumOptionCount: ballotPrivacyMinimumOptionCount,
        maximumOptionCount: ballotPrivacyMaximumOptionCount,
        shareVectorWidth,
        widthFormula: 'shareVectorWidth = 11 * optionCount',
        paddingRule: 'unused coordinates must be zero',
    };

    return {
        ...profilePayload,
        ballotShareLayoutProfileDigest:
            deriveBallotShareLayoutProfileDigest(profilePayload),
    };
};

const createAggregateInputEncodingProfile =
    (): AggregateInputEncodingProfile => {
        const profilePayload: AggregateInputEncodingProfilePayload = {
            objectType: 'AggregateInputEncodingProfile',
            objectVersion: 1,
            profileId: aggregateInputEncodingProfileId,
            encoding: 'AggregatedScoreHistogram',
            scalarAggregateCoordinates: true,
            oneHotBucketAggregateCoordinates: true,
            coordinatesPerOption: ballotPrivacyEncodedCoordinatesPerOption,
            maximumOptionCount: ballotPrivacyMaximumOptionCount,
        };

        return {
            ...profilePayload,
            aggregateInputEncodingProfileDigest:
                deriveAggregateInputEncodingProfileDigest(profilePayload),
        };
    };

const createEncodedShareVectorLayoutProfile = (
    shareVectorWidth: number,
): EncodedShareVectorLayoutProfile => {
    const profilePayload: EncodedShareVectorLayoutProfilePayload = {
        objectType: 'EncodedShareVectorLayoutProfile',
        objectVersion: 1,
        profileId: encodedShareVectorLayoutProfileId,
        layout: 'ScalarThenOneHotBucketsPerOption',
        coordinatesPerOption: ballotPrivacyEncodedCoordinatesPerOption,
        maximumOptionCount: ballotPrivacyMaximumOptionCount,
        shareVectorWidth,
        coordinateOrder:
            'score, score_bucket_1, ..., score_bucket_10 for each option',
    };

    return {
        ...profilePayload,
        encodedShareVectorLayoutDigest:
            deriveEncodedShareVectorLayoutDigest(profilePayload),
    };
};

const createEncodedAggregateLayoutProfile = (
    aggregateWidth: number,
): EncodedAggregateLayoutProfile => {
    const profilePayload: EncodedAggregateLayoutProfilePayload = {
        objectType: 'EncodedAggregateLayoutProfile',
        objectVersion: 1,
        profileId: encodedAggregateLayoutProfileId,
        layout: 'AggregatedScalarAndScoreBucketCoordinates',
        coordinatesPerOption: ballotPrivacyEncodedCoordinatesPerOption,
        maximumOptionCount: ballotPrivacyMaximumOptionCount,
        aggregateWidth,
        aggregateCoordinateMeaning:
            'sum of accepted receiver-share coordinates before bridge reduction',
    };

    return {
        ...profilePayload,
        encodedAggregateLayoutDigest:
            deriveEncodedAggregateLayoutDigest(profilePayload),
    };
};

const createBallotProofProfile = (): BallotProofProfile => {
    // This profile records the selected proof target. Current implementation
    // evidence and claim limits are tracked in CURRENT_STATUS.md; do not treat
    // these fields as final theorem eligibility by themselves.
    const profilePayload: BallotProofProfilePayload = {
        objectType: 'BallotProofProfile',
        objectVersion: 1,
        profileId: ballotProofProfileId,
        proofSystem: 'LocalLinearLatticeRelation',
        backendConstruction: 'LyubashevskyNguyenPlancon2022LinearProofs',
        relationShape:
            'LinearLatticeRelationsWithShortVectorAndOneHotMembership',
        fiatShamirHash: 'SHAKE128-256',
        fiatShamirModel: 'QROMAccountedRequired',
        challengeBits: 256,
        soundnessBits: 128,
        proofSizeTargetBytesMandatoryProfile:
            mandatoryProfileProofSizeTargetBytes,
        proofSizeTargetBytesCertificateGatedProfile:
            certificateGatedProfileProofSizeTargetBytes,
        constantShapeForFixedRosterAndOptionCount: true,
        postQuantumClaim: true,
        pairingBasedWrapExcluded: true,
    };

    return {
        ...profilePayload,
        ballotProofProfileDigest:
            deriveBallotProofProfileDigest(profilePayload),
    };
};

export const createBallotPrivacyProfileSet = (
    input: BallotPrivacyProfileSetInput = {},
): BallotPrivacyProfileSet => {
    const optionCount = normalizeProfileOptionCount(
        input.optionCount ?? defaultProfileOptionCount,
    );
    const shareVectorWidth =
        getBallotPrivacyEncodedShareVectorWidth(optionCount);

    return {
        receiverEncryptionProfile: createReceiverEncryptionProfile(),
        shareCommitmentProfile: createShareCommitmentProfile(shareVectorWidth),
        scoreMembershipProfile: createScoreMembershipProfile(),
        ballotScoreEncodingProfile: createBallotScoreEncodingProfile(),
        ballotShareLayoutProfile:
            createBallotShareLayoutProfile(shareVectorWidth),
        aggregateInputEncodingProfile: createAggregateInputEncodingProfile(),
        encodedShareVectorLayoutProfile:
            createEncodedShareVectorLayoutProfile(shareVectorWidth),
        encodedAggregateLayoutProfile:
            createEncodedAggregateLayoutProfile(shareVectorWidth),
        ballotProofProfile: createBallotProofProfile(),
    };
};

export const deriveBallotPrivacyProfileDigests =
    (): BallotPrivacyProfileDigests => {
        const profileSet = createBallotPrivacyProfileSet();

        return {
            receiverEncryptionProfileDigest:
                profileSet.receiverEncryptionProfile
                    .receiverEncryptionProfileDigest,
            shareCommitmentProfileDigest:
                profileSet.shareCommitmentProfile.shareCommitmentProfileDigest,
            scoreMembershipProfileDigest:
                profileSet.scoreMembershipProfile.scoreMembershipProfileDigest,
            ballotScoreEncodingProfileDigest:
                profileSet.ballotScoreEncodingProfile
                    .ballotScoreEncodingProfileDigest,
            ballotShareLayoutProfileDigest:
                profileSet.ballotShareLayoutProfile
                    .ballotShareLayoutProfileDigest,
            aggregateInputEncodingProfileDigest:
                profileSet.aggregateInputEncodingProfile
                    .aggregateInputEncodingProfileDigest,
            encodedShareVectorLayoutDigest:
                profileSet.encodedShareVectorLayoutProfile
                    .encodedShareVectorLayoutDigest,
            encodedAggregateLayoutDigest:
                profileSet.encodedAggregateLayoutProfile
                    .encodedAggregateLayoutDigest,
            ballotProofProfileDigest:
                profileSet.ballotProofProfile.ballotProofProfileDigest,
        };
    };

export const createShareCommitmentMessageBoundCert = (input: {
    readonly maximumCanonicalTurnout: number;
    readonly shareCommitmentProfile?: ShareCommitmentProfile;
}): ShareCommitmentMessageBoundCert => {
    const maximumCanonicalTurnout = input.maximumCanonicalTurnout;
    if (
        !Number.isSafeInteger(maximumCanonicalTurnout) ||
        maximumCanonicalTurnout < minimumSupportedTurnout ||
        maximumCanonicalTurnout > maximumCertificateGatedTurnout
    ) {
        throw new RangeError(
            'Share commitment message-bound certificates require a supported canonical turnout.',
        );
    }

    const shareCommitmentProfile =
        input.shareCommitmentProfile ??
        createShareCommitmentProfile(
            getBallotPrivacyEncodedShareVectorWidth(defaultProfileOptionCount),
        );
    const maximumAggregateInteger =
        maximumCanonicalTurnout * (fieldModulus - 1);
    const openingRandomnessAggregateBound =
        maximumCanonicalTurnout *
        shareCommitmentProfile.openingRandomnessInfinityNormBound;
    const profileDigest = deriveProtocolDigest(
        'ShareCommitmentMessageBoundCertDigest',
        {
            fieldEncodingProfileId,
            profileId: shareCommitmentMessageBoundProfileId,
            shareCommitmentProfileDigest:
                shareCommitmentProfile.shareCommitmentProfileDigest,
        },
    );
    const certificatePayload: ShareCommitmentMessageBoundCertPayload = {
        objectType: 'ShareCommitmentMessageBoundCert',
        objectVersion: 1,
        profileId: shareCommitmentMessageBoundProfileId,
        profileDigest,
        shareCommitmentProfileDigest:
            shareCommitmentProfile.shareCommitmentProfileDigest,
        fieldModulus,
        shareVectorWidth: shareCommitmentProfile.shareVectorWidth,
        perBallotShareRepresentativeRange: [0, maximumCanonicalFieldElement],
        maximumCanonicalTurnout,
        maximumAggregateInteger,
        commitmentMessageBound,
        openingRandomnessSingleBound:
            shareCommitmentProfile.openingRandomnessInfinityNormBound,
        openingRandomnessAggregateBound,
        quotientBoundForAggregateReduction: maximumCanonicalTurnout,
        noWraparoundCondition: {
            maximumAggregateIntegerLessThanCommitmentMessageBound: true,
            openingRandomnessAggregateBoundMatchesTurnout: true,
        },
    };

    return {
        ...certificatePayload,
        shareCommitmentMessageBoundCertDigest:
            deriveShareCommitmentMessageBoundCertDigest(certificatePayload),
    };
};

const verifyCanonicalDigest = (input: {
    readonly certificate: ShareCommitmentMessageBoundCert;
    readonly refusedObjects: RefusalRecord[];
}): void => {
    const {
        shareCommitmentMessageBoundCertDigest,
        ...certificateWithoutDigest
    } = input.certificate;
    let expectedDigest: ProtocolDigest;
    try {
        expectedDigest = deriveShareCommitmentMessageBoundCertDigest(
            certificateWithoutDigest,
        );
    } catch {
        input.refusedObjects.push(
            createRefusal(
                'BallotPrivacyProfileInvalid',
                'Share commitment message-bound certificate payload is not canonical.',
                shareCommitmentMessageBoundCertDigest,
            ),
        );

        return;
    }

    if (shareCommitmentMessageBoundCertDigest !== expectedDigest) {
        input.refusedObjects.push(
            createRefusal(
                'BallotPrivacyProfileInvalid',
                'Share commitment message-bound certificate digest does not match its canonical payload.',
                shareCommitmentMessageBoundCertDigest,
            ),
        );
    }
};

export const verifyShareCommitmentMessageBoundCert = (input: {
    readonly certificate: ShareCommitmentMessageBoundCert;
    readonly expectedMaximumCanonicalTurnout?: number;
    readonly expectedShareCommitmentProfileDigest?: ProtocolDigest;
}): ShareCommitmentMessageBoundCertVerification => {
    const refusedObjects: RefusalRecord[] = [];
    const certificate = input.certificate;

    verifyCanonicalDigest({ certificate, refusedObjects });

    const expectedOpeningRandomnessAggregateBound =
        certificate.maximumCanonicalTurnout *
        certificate.openingRandomnessSingleBound;

    if (
        certificate.objectType !== 'ShareCommitmentMessageBoundCert' ||
        certificate.objectVersion !== 1 ||
        certificate.profileId !== shareCommitmentMessageBoundProfileId ||
        certificate.fieldModulus !== fieldModulus ||
        !Number.isSafeInteger(certificate.shareVectorWidth) ||
        certificate.shareVectorWidth <= 0 ||
        certificate.perBallotShareRepresentativeRange[0] !== 0 ||
        certificate.perBallotShareRepresentativeRange[1] !== fieldModulus - 1
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPrivacyProfileInvalid',
                'Share commitment message-bound certificate shape is not canonical.',
                certificate.shareCommitmentMessageBoundCertDigest,
            ),
        );
    }
    if (
        input.expectedMaximumCanonicalTurnout !== undefined &&
        certificate.maximumCanonicalTurnout !==
            input.expectedMaximumCanonicalTurnout
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPrivacyProfileInvalid',
                'Share commitment message-bound certificate turnout does not match the expected profile.',
                certificate.shareCommitmentMessageBoundCertDigest,
            ),
        );
    }
    if (
        input.expectedShareCommitmentProfileDigest !== undefined &&
        certificate.shareCommitmentProfileDigest !==
            input.expectedShareCommitmentProfileDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPrivacyProfileInvalid',
                'Share commitment message-bound certificate is not bound to the expected share commitment profile.',
                certificate.shareCommitmentMessageBoundCertDigest,
            ),
        );
    }
    if (
        certificate.maximumAggregateInteger !==
            certificate.maximumCanonicalTurnout * (fieldModulus - 1) ||
        certificate.openingRandomnessAggregateBound !==
            expectedOpeningRandomnessAggregateBound ||
        certificate.quotientBoundForAggregateReduction !==
            certificate.maximumCanonicalTurnout
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPrivacyProfileInvalid',
                'Share commitment message-bound certificate bounds are inconsistent.',
                certificate.shareCommitmentMessageBoundCertDigest,
            ),
        );
    }
    const maximumAggregateIntegerIsCanonical = isNonNegativeInteger(
        certificate.maximumAggregateInteger,
    );
    const aggregateCanWrap =
        !maximumAggregateIntegerIsCanonical ||
        !decimalIntegerPattern.test(certificate.commitmentMessageBound) ||
        compareDecimalIntegerStrings(
            String(certificate.maximumAggregateInteger),
            certificate.commitmentMessageBound,
        ) >= 0;

    if (aggregateCanWrap) {
        refusedObjects.push(
            createRefusal(
                'BallotPrivacyProfileInvalid',
                'Share commitment message-bound certificate permits aggregate share wraparound.',
                certificate.shareCommitmentMessageBoundCertDigest,
            ),
        );
    }
    if (
        !certificate.noWraparoundCondition
            .maximumAggregateIntegerLessThanCommitmentMessageBound ||
        !certificate.noWraparoundCondition
            .openingRandomnessAggregateBoundMatchesTurnout
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPrivacyProfileInvalid',
                'Share commitment message-bound certificate no-wraparound flags are not satisfied.',
                certificate.shareCommitmentMessageBoundCertDigest,
            ),
        );
    }

    if (refusedObjects.length > 0) {
        return {
            ok: false,
            statusLabels: [],
            acceptedDigests: [],
            refusedObjects,
            unresolvedReason: 'BallotPrivacyProfileInvalid',
        };
    }

    return {
        ok: true,
        statusLabels: [],
        acceptedDigests: [certificate.shareCommitmentMessageBoundCertDigest],
        refusedObjects: [],
        shareCommitmentMessageBoundCertDigest:
            certificate.shareCommitmentMessageBoundCertDigest,
    };
};
