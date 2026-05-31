import { deriveProtocolHash } from '@sealed-lattice/crypto';
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
    type BallotPrivacyProfileHashes,
    type BallotPrivacyProfileSet,
    type BallotProofProfile,
    type EncodedAggregateLayoutProfile,
    type EncodedShareVectorLayoutProfile,
    type ProtocolHash,
    type ReceiverEncryptionProfile,
    type RefusalRecord,
    type ScoreMembershipProfile,
    type ShareCommitmentMessageBoundCert,
    type ShareCommitmentMessageBoundCertVerification,
    type ShareCommitmentProfile,
} from '@sealed-lattice/types';

import { fieldModulus } from './plaintext-oracle-helpers.js';
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
import { createRefusal, isNonNegativeInteger } from './verification-helpers.js';

const decimalIntegerPattern = /^(0|[1-9][0-9]*)$/u;

type ReceiverEncryptionProfilePayload = Omit<
    ReceiverEncryptionProfile,
    'receiverEncryptionProfileHash'
>;
type ShareCommitmentProfilePayload = Omit<
    ShareCommitmentProfile,
    'shareCommitmentProfileHash'
>;
type ScoreMembershipProfilePayload = Omit<
    ScoreMembershipProfile,
    'scoreMembershipProfileHash'
>;
type BallotScoreEncodingProfilePayload = Omit<
    BallotScoreEncodingProfile,
    'ballotScoreEncodingProfileHash'
>;
type BallotShareLayoutProfilePayload = Omit<
    BallotShareLayoutProfile,
    'ballotShareLayoutProfileHash'
>;
type AggregateInputEncodingProfilePayload = Omit<
    AggregateInputEncodingProfile,
    'aggregateInputEncodingProfileHash'
>;
type EncodedShareVectorLayoutProfilePayload = Omit<
    EncodedShareVectorLayoutProfile,
    'encodedShareVectorLayoutHash'
>;
type EncodedAggregateLayoutProfilePayload = Omit<
    EncodedAggregateLayoutProfile,
    'encodedAggregateLayoutHash'
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
    'ballotProofProfileHash'
>;
type ShareCommitmentMessageBoundCertPayload = Omit<
    ShareCommitmentMessageBoundCert,
    'shareCommitmentMessageBoundCertHash'
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

const deriveReceiverEncryptionProfileHash = (
    profile: ReceiverEncryptionProfilePayload,
): ProtocolHash => deriveProtocolHash('ReceiverEncryptionProfileHash', profile);

const deriveShareCommitmentProfileHash = (
    profile: ShareCommitmentProfilePayload,
): ProtocolHash => deriveProtocolHash('ShareCommitmentProfileHash', profile);

const deriveScoreMembershipProfileHash = (
    profile: ScoreMembershipProfilePayload,
): ProtocolHash => deriveProtocolHash('ScoreMembershipProfileHash', profile);

const deriveBallotScoreEncodingProfileHash = (
    profile: BallotScoreEncodingProfilePayload,
): ProtocolHash =>
    deriveProtocolHash('BallotScoreEncodingProfileHash', profile);

const deriveBallotShareLayoutProfileHash = (
    profile: BallotShareLayoutProfilePayload,
): ProtocolHash => deriveProtocolHash('BallotShareLayoutProfileHash', profile);

const deriveAggregateInputEncodingProfileHash = (
    profile: AggregateInputEncodingProfilePayload,
): ProtocolHash =>
    deriveProtocolHash('AggregateInputEncodingProfileHash', profile);

const deriveEncodedShareVectorLayoutHash = (
    profile: EncodedShareVectorLayoutProfilePayload,
): ProtocolHash => deriveProtocolHash('EncodedShareVectorLayoutHash', profile);

const deriveEncodedAggregateLayoutHash = (
    profile: EncodedAggregateLayoutProfilePayload,
): ProtocolHash => deriveProtocolHash('EncodedAggregateLayoutHash', profile);

const deriveBallotProofProfileHash = (
    profile: BallotProofProfilePayload,
): ProtocolHash => deriveProtocolHash('BallotProofProfileHash', profile);

export const deriveShareCommitmentMessageBoundCertHash = (
    certificate: ShareCommitmentMessageBoundCertPayload,
): ProtocolHash =>
    deriveProtocolHash('ShareCommitmentMessageBoundCertHash', certificate);

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
            bindsManifestHash: true,
            bindsRosterHash: true,
            bindsPollSpecHash: true,
            bindsVoterIdentityHash: true,
            bindsActionContextHash: true,
        },
        decryptionFailureTarget: '2^-128',
    };

    return {
        ...profilePayload,
        receiverEncryptionProfileHash:
            deriveReceiverEncryptionProfileHash(profilePayload),
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
        shareCommitmentProfileHash:
            deriveShareCommitmentProfileHash(profilePayload),
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
        scoreMembershipProfileHash:
            deriveScoreMembershipProfileHash(profilePayload),
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
        ballotScoreEncodingProfileHash:
            deriveBallotScoreEncodingProfileHash(profilePayload),
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
        ballotShareLayoutProfileHash:
            deriveBallotShareLayoutProfileHash(profilePayload),
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
            aggregateInputEncodingProfileHash:
                deriveAggregateInputEncodingProfileHash(profilePayload),
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
        encodedShareVectorLayoutHash:
            deriveEncodedShareVectorLayoutHash(profilePayload),
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
        encodedAggregateLayoutHash:
            deriveEncodedAggregateLayoutHash(profilePayload),
    };
};

const createBallotProofProfile = (): BallotProofProfile => {
    // This profile records the selected proof target. Current implementation
    // evidence and claim limits are tracked in README.md; do not treat
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
        ballotProofProfileHash: deriveBallotProofProfileHash(profilePayload),
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

export const deriveBallotPrivacyProfileHashes =
    (): BallotPrivacyProfileHashes => {
        const profileSet = createBallotPrivacyProfileSet();

        return {
            receiverEncryptionProfileHash:
                profileSet.receiverEncryptionProfile
                    .receiverEncryptionProfileHash,
            shareCommitmentProfileHash:
                profileSet.shareCommitmentProfile.shareCommitmentProfileHash,
            scoreMembershipProfileHash:
                profileSet.scoreMembershipProfile.scoreMembershipProfileHash,
            ballotScoreEncodingProfileHash:
                profileSet.ballotScoreEncodingProfile
                    .ballotScoreEncodingProfileHash,
            ballotShareLayoutProfileHash:
                profileSet.ballotShareLayoutProfile
                    .ballotShareLayoutProfileHash,
            aggregateInputEncodingProfileHash:
                profileSet.aggregateInputEncodingProfile
                    .aggregateInputEncodingProfileHash,
            encodedShareVectorLayoutHash:
                profileSet.encodedShareVectorLayoutProfile
                    .encodedShareVectorLayoutHash,
            encodedAggregateLayoutHash:
                profileSet.encodedAggregateLayoutProfile
                    .encodedAggregateLayoutHash,
            ballotProofProfileHash:
                profileSet.ballotProofProfile.ballotProofProfileHash,
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
    const profileHash = deriveProtocolHash(
        'ShareCommitmentMessageBoundCertHash',
        {
            fieldEncodingProfileId,
            profileId: shareCommitmentMessageBoundProfileId,
            shareCommitmentProfileHash:
                shareCommitmentProfile.shareCommitmentProfileHash,
        },
    );
    const certificatePayload: ShareCommitmentMessageBoundCertPayload = {
        objectType: 'ShareCommitmentMessageBoundCert',
        objectVersion: 1,
        profileId: shareCommitmentMessageBoundProfileId,
        profileHash,
        shareCommitmentProfileHash:
            shareCommitmentProfile.shareCommitmentProfileHash,
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
        shareCommitmentMessageBoundCertHash:
            deriveShareCommitmentMessageBoundCertHash(certificatePayload),
    };
};

const verifyCanonicalHash = (input: {
    readonly certificate: ShareCommitmentMessageBoundCert;
    readonly refusedObjects: RefusalRecord[];
}): void => {
    const { shareCommitmentMessageBoundCertHash, ...certificateWithoutHash } =
        input.certificate;
    let expectedHash: ProtocolHash;
    try {
        expectedHash = deriveShareCommitmentMessageBoundCertHash(
            certificateWithoutHash,
        );
    } catch {
        input.refusedObjects.push(
            createRefusal(
                'BallotPrivacyProfileInvalid',
                'Share commitment message-bound certificate payload is not canonical.',
                shareCommitmentMessageBoundCertHash,
            ),
        );

        return;
    }

    if (shareCommitmentMessageBoundCertHash !== expectedHash) {
        input.refusedObjects.push(
            createRefusal(
                'BallotPrivacyProfileInvalid',
                'Share commitment message-bound certificate hash does not match its canonical payload.',
                shareCommitmentMessageBoundCertHash,
            ),
        );
    }
};

export const verifyShareCommitmentMessageBoundCert = (input: {
    readonly certificate: ShareCommitmentMessageBoundCert;
    readonly expectedMaximumCanonicalTurnout?: number;
    readonly expectedShareCommitmentProfileHash?: ProtocolHash;
}): ShareCommitmentMessageBoundCertVerification => {
    const refusedObjects: RefusalRecord[] = [];
    const certificate = input.certificate;

    verifyCanonicalHash({ certificate, refusedObjects });

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
                certificate.shareCommitmentMessageBoundCertHash,
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
                certificate.shareCommitmentMessageBoundCertHash,
            ),
        );
    }
    if (
        input.expectedShareCommitmentProfileHash !== undefined &&
        certificate.shareCommitmentProfileHash !==
            input.expectedShareCommitmentProfileHash
    ) {
        refusedObjects.push(
            createRefusal(
                'BallotPrivacyProfileInvalid',
                'Share commitment message-bound certificate is not bound to the expected share commitment profile.',
                certificate.shareCommitmentMessageBoundCertHash,
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
                certificate.shareCommitmentMessageBoundCertHash,
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
                certificate.shareCommitmentMessageBoundCertHash,
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
                certificate.shareCommitmentMessageBoundCertHash,
            ),
        );
    }

    if (refusedObjects.length > 0) {
        return {
            ok: false,
            statusLabels: [],
            acceptedHashes: [],
            refusedObjects,
            unresolvedReason: 'BallotPrivacyProfileInvalid',
        };
    }

    return {
        ok: true,
        statusLabels: [],
        acceptedHashes: [certificate.shareCommitmentMessageBoundCertHash],
        refusedObjects: [],
        shareCommitmentMessageBoundCertHash:
            certificate.shareCommitmentMessageBoundCertHash,
    };
};
