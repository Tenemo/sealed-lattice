import { protocolHashNamespaceValues } from '@sealed-lattice/types';
import type { ShareCommitmentMessageBoundCert } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    createBallotPrivacyProfileSet,
    createShareCommitmentMessageBoundCert,
    deriveBallotPrivacyProfileHashes,
    deriveShareCommitmentMessageBoundCertHash,
    verifyShareCommitmentMessageBoundCert,
} from '#packages/protocol/src/ballot-privacy/index';
import ballotPrivacyProfileVectorJson from '#test-vectors/ballot-privacy/proof-stack-profile.json' with { type: 'json' };

const ballotPrivacyProfileVector = ballotPrivacyProfileVectorJson as {
    readonly schemaVersion: 1;
    readonly profileIds: {
        readonly receiverEncryptionProfileId: string;
        readonly shareCommitmentProfileId: string;
        readonly scoreMembershipProfileId: string;
        readonly ballotScoreEncodingProfileId: string;
        readonly ballotShareLayoutProfileId: string;
        readonly aggregateInputEncodingProfileId: string;
        readonly encodedShareVectorLayoutProfileId: string;
        readonly encodedAggregateLayoutProfileId: string;
        readonly ballotProofProfileId: string;
    };
    readonly profileHashes: {
        readonly receiverEncryptionProfileHash: string;
        readonly shareCommitmentProfileHash: string;
        readonly scoreMembershipProfileHash: string;
        readonly ballotScoreEncodingProfileHash: string;
        readonly ballotShareLayoutProfileHash: string;
        readonly aggregateInputEncodingProfileHash: string;
        readonly encodedShareVectorLayoutHash: string;
        readonly encodedAggregateLayoutHash: string;
        readonly ballotProofProfileHash: string;
    };
    readonly mandatoryBoundCert: {
        readonly shareCommitmentMessageBoundCertHash: string;
        readonly maximumCanonicalTurnout: number;
        readonly maximumAggregateInteger: number;
        readonly openingRandomnessAggregateBound: number;
    };
    readonly certificateGatedBoundCert: {
        readonly shareCommitmentMessageBoundCertHash: string;
        readonly maximumCanonicalTurnout: number;
        readonly maximumAggregateInteger: number;
        readonly openingRandomnessAggregateBound: number;
    };
};

const reHashCertificate = (
    certificate: ShareCommitmentMessageBoundCert,
): ShareCommitmentMessageBoundCert => {
    const certificateWithoutHash: Omit<
        ShareCommitmentMessageBoundCert,
        'shareCommitmentMessageBoundCertHash'
    > = {
        objectType: certificate.objectType,
        objectVersion: certificate.objectVersion,
        profileId: certificate.profileId,
        profileHash: certificate.profileHash,
        shareCommitmentProfileHash: certificate.shareCommitmentProfileHash,
        fieldModulus: certificate.fieldModulus,
        shareVectorWidth: certificate.shareVectorWidth,
        perBallotShareRepresentativeRange:
            certificate.perBallotShareRepresentativeRange,
        maximumCanonicalTurnout: certificate.maximumCanonicalTurnout,
        maximumAggregateInteger: certificate.maximumAggregateInteger,
        commitmentMessageBound: certificate.commitmentMessageBound,
        openingRandomnessSingleBound: certificate.openingRandomnessSingleBound,
        openingRandomnessAggregateBound:
            certificate.openingRandomnessAggregateBound,
        quotientBoundForAggregateReduction:
            certificate.quotientBoundForAggregateReduction,
        noWraparoundCondition: certificate.noWraparoundCondition,
    };

    return {
        ...certificateWithoutHash,
        shareCommitmentMessageBoundCertHash:
            deriveShareCommitmentMessageBoundCertHash(certificateWithoutHash),
    };
};

describe('ballot privacy profile freeze', () => {
    it('freezes production-shaped profile choices without using transport KEM as receiver encryption', () => {
        const profileSet = createBallotPrivacyProfileSet();
        const profileHashes = deriveBallotPrivacyProfileHashes();

        expect(profileSet.receiverEncryptionProfile.profileId).toBe(
            ballotPrivacyProfileVector.profileIds.receiverEncryptionProfileId,
        );
        expect(profileSet.receiverEncryptionProfile.scheme).toBe(
            'LinearModuleLweRegev',
        );
        expect(profileSet.receiverEncryptionProfile.profileId).not.toContain(
            'ML-KEM',
        );
        expect(
            profileSet.receiverEncryptionProfile.payloadBinding,
        ).toMatchObject({
            encryptsReceiverShareVector: true,
            encryptsShareCommitmentOpening: true,
            bindsActionContextHash: true,
        });
        expect(profileSet.shareCommitmentProfile.profileId).toBe(
            ballotPrivacyProfileVector.profileIds.shareCommitmentProfileId,
        );
        expect(profileSet.shareCommitmentProfile.commitmentFormula).toContain(
            'EncodeShareVector(S)',
        );
        expect(profileSet.scoreMembershipProfile.profileId).toBe(
            ballotPrivacyProfileVector.profileIds.scoreMembershipProfileId,
        );
        expect(profileSet.scoreMembershipProfile.relation).toBe(
            'OneHotScoreMembership',
        );
        expect(profileSet.ballotScoreEncodingProfile.profileId).toBe(
            ballotPrivacyProfileVector.profileIds.ballotScoreEncodingProfileId,
        );
        expect(profileSet.ballotShareLayoutProfile.profileId).toBe(
            ballotPrivacyProfileVector.profileIds.ballotShareLayoutProfileId,
        );
        expect(profileSet.aggregateInputEncodingProfile.profileId).toBe(
            ballotPrivacyProfileVector.profileIds
                .aggregateInputEncodingProfileId,
        );
        expect(profileSet.encodedShareVectorLayoutProfile.profileId).toBe(
            ballotPrivacyProfileVector.profileIds
                .encodedShareVectorLayoutProfileId,
        );
        expect(profileSet.encodedAggregateLayoutProfile.profileId).toBe(
            ballotPrivacyProfileVector.profileIds
                .encodedAggregateLayoutProfileId,
        );
        expect(profileSet.shareCommitmentProfile.shareVectorWidth).toBe(220);
        expect(
            profileSet.shareCommitmentProfile.openingRandomnessDistribution,
        ).toBe('UniformCenteredInteger');
        expect(profileSet.shareCommitmentProfile.openingRandomnessSampler).toBe(
            'RejectionSampledLittleEndianUint16',
        );
        expect(
            profileSet.shareCommitmentProfile.openingRandomnessRangeWidth,
        ).toBe(2049);
        expect(
            profileSet.shareCommitmentProfile.openingRandomnessSamplerDomain,
        ).toBe('sealed.vote/internal/share-commitment/opening-randomness-v1');
        expect(profileSet.ballotShareLayoutProfile.shareVectorWidth).toBe(220);
        expect(
            createBallotPrivacyProfileSet({ optionCount: 2 })
                .ballotShareLayoutProfile.shareVectorWidth,
        ).toBe(22);
        expect(profileSet.ballotProofProfile.profileId).toBe(
            ballotPrivacyProfileVector.profileIds.ballotProofProfileId,
        );
        expect(profileSet.ballotProofProfile.fiatShamirModel).toBe(
            'QROMAccountedRequired',
        );
        expect(profileSet.ballotProofProfile.challengeBits).toBe(256);
        expect(profileSet.ballotProofProfile.soundnessBits).toBe(128);
        expect(profileHashes).toEqual(ballotPrivacyProfileVector.profileHashes);
    });

    it('creates bound certificates for mandatory and certificate-gated turnout without tally-style share bounds', () => {
        const profileSet = createBallotPrivacyProfileSet();
        const mandatoryCertificate = createShareCommitmentMessageBoundCert({
            maximumCanonicalTurnout: 20,
            shareCommitmentProfile: profileSet.shareCommitmentProfile,
        });
        const certificateGatedCertificate =
            createShareCommitmentMessageBoundCert({
                maximumCanonicalTurnout: 50,
                shareCommitmentProfile: profileSet.shareCommitmentProfile,
            });

        expect(mandatoryCertificate.maximumAggregateInteger).toBe(20 * 65_536);
        expect(mandatoryCertificate.maximumAggregateInteger).not.toBe(20 * 10);
        expect(certificateGatedCertificate.maximumAggregateInteger).toBe(
            50 * 65_536,
        );
        expect(
            verifyShareCommitmentMessageBoundCert({
                certificate: mandatoryCertificate,
                expectedMaximumCanonicalTurnout: 20,
                expectedShareCommitmentProfileHash:
                    profileSet.shareCommitmentProfile
                        .shareCommitmentProfileHash,
            }).ok,
        ).toBe(true);
        expect(
            verifyShareCommitmentMessageBoundCert({
                certificate: certificateGatedCertificate,
                expectedMaximumCanonicalTurnout: 50,
                expectedShareCommitmentProfileHash:
                    profileSet.shareCommitmentProfile
                        .shareCommitmentProfileHash,
            }).ok,
        ).toBe(true);
        expect(mandatoryCertificate).toMatchObject(
            ballotPrivacyProfileVector.mandatoryBoundCert,
        );
        expect(certificateGatedCertificate).toMatchObject(
            ballotPrivacyProfileVector.certificateGatedBoundCert,
        );
    });

    it('rejects inconsistent, wrapping, or wrongly bound share-commitment certificates', () => {
        const profileSet = createBallotPrivacyProfileSet();
        const certificate = createShareCommitmentMessageBoundCert({
            maximumCanonicalTurnout: 20,
            shareCommitmentProfile: profileSet.shareCommitmentProfile,
        });
        const wrongHashCertificate: ShareCommitmentMessageBoundCert = {
            ...certificate,
            shareCommitmentMessageBoundCertHash: '0'.repeat(128),
        };
        const wrappingCertificate = reHashCertificate({
            ...certificate,
            commitmentMessageBound: String(
                certificate.maximumAggregateInteger - 1,
            ),
        });
        const inconsistentOpeningCertificate = reHashCertificate({
            ...certificate,
            openingRandomnessAggregateBound:
                certificate.openingRandomnessAggregateBound + 1,
        });

        expect(
            verifyShareCommitmentMessageBoundCert({
                certificate: wrongHashCertificate,
            }).refusedObjects.map((refusal) => refusal.code),
        ).toContain('BallotPrivacyProfileInvalid');
        expect(
            verifyShareCommitmentMessageBoundCert({
                certificate: wrappingCertificate,
            }).refusedObjects.map((refusal) => refusal.message),
        ).toContain(
            'Share commitment message-bound certificate permits aggregate share wraparound.',
        );
        expect(
            verifyShareCommitmentMessageBoundCert({
                certificate: inconsistentOpeningCertificate,
            }).refusedObjects.map((refusal) => refusal.message),
        ).toContain(
            'Share commitment message-bound certificate bounds are inconsistent.',
        );
        expect(
            verifyShareCommitmentMessageBoundCert({
                certificate,
                expectedShareCommitmentProfileHash: '1'.repeat(128),
            }).refusedObjects.map((refusal) => refusal.message),
        ).toContain(
            'Share commitment message-bound certificate is not bound to the expected share commitment profile.',
        );
    });

    it('returns refusals instead of throwing for malformed aggregate bounds', () => {
        const profileSet = createBallotPrivacyProfileSet();
        const certificate = createShareCommitmentMessageBoundCert({
            maximumCanonicalTurnout: 20,
            shareCommitmentProfile: profileSet.shareCommitmentProfile,
        });

        for (const malformedMaximumAggregateInteger of [Number.NaN, -1, 1.5]) {
            expect(() =>
                verifyShareCommitmentMessageBoundCert({
                    certificate: {
                        ...certificate,
                        maximumAggregateInteger:
                            malformedMaximumAggregateInteger,
                    },
                }),
            ).not.toThrow();
            expect(
                verifyShareCommitmentMessageBoundCert({
                    certificate: {
                        ...certificate,
                        maximumAggregateInteger:
                            malformedMaximumAggregateInteger,
                    },
                }).refusedObjects.map((refusal) => refusal.code),
            ).toContain('BallotPrivacyProfileInvalid');
        }
    });

    it('reserves every ballot privacy hash namespace in the shared registry', () => {
        expect(protocolHashNamespaceValues).toEqual(
            expect.arrayContaining([
                'ReceiverEncryptionProfileHash',
                'ShareCommitmentProfileHash',
                'BallotProofProfileHash',
                'ScoreMembershipProfileHash',
                'BallotScoreEncodingProfileHash',
                'BallotShareLayoutProfileHash',
                'AggregateInputEncodingProfileHash',
                'EncodedShareVectorLayoutHash',
                'EncodedAggregateLayoutHash',
                'ShareCommitmentMessageBoundCertHash',
                'ReceiverPayloadHash',
                'ReceiverPayloadCiphertextRoot',
                'ReceiverKeyProofRoot',
                'BallotProofStatementHash',
                'BallotProofRecordHash',
                'ProofBytesHash',
                'ChallengeDomainHash',
            ]),
        );
    });

    it('keeps receiver encryption parameter security evidence marked incomplete', () => {
        const profileSet = createBallotPrivacyProfileSet();

        expect(
            profileSet.receiverEncryptionProfile
                .parameterSecurityEvidenceStatus,
        ).toBe('ParameterCertificateMissing');
        expect(profileSet.receiverEncryptionProfile.claimBoundary).toBe(
            'ReceiverEncryptionParameterSecurityNotClosed',
        );
    });
});
