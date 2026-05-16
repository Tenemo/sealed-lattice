import { protocolDigestNamespaceValues } from '@sealed-lattice/types';
import type { ShareCommitmentMessageBoundCert } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import ballotPrivacyProfileVectorJson from '../../../../test-vectors/ballot-privacy/proof-stack-profile.json' with { type: 'json' };
import {
    createBallotPrivacyProfileSet,
    createShareCommitmentMessageBoundCert,
    deriveBallotPrivacyProfileDigests,
    deriveShareCommitmentMessageBoundCertDigest,
    verifyShareCommitmentMessageBoundCert,
} from '../../src/ballot-privacy/index';

const ballotPrivacyProfileVector = ballotPrivacyProfileVectorJson as {
    readonly schemaVersion: 1;
    readonly profileIds: {
        readonly receiverEncryptionProfileId: string;
        readonly shareCommitmentProfileId: string;
        readonly scoreMembershipProfileId: string;
        readonly ballotProofProfileId: string;
    };
    readonly profileDigests: {
        readonly receiverEncryptionProfileDigest: string;
        readonly shareCommitmentProfileDigest: string;
        readonly scoreMembershipProfileDigest: string;
        readonly ballotProofProfileDigest: string;
    };
    readonly mandatoryBoundCert: {
        readonly shareCommitmentMessageBoundCertDigest: string;
        readonly maximumCanonicalTurnout: number;
        readonly maximumAggregateInteger: number;
        readonly openingRandomnessAggregateBound: number;
    };
    readonly certificateGatedBoundCert: {
        readonly shareCommitmentMessageBoundCertDigest: string;
        readonly maximumCanonicalTurnout: number;
        readonly maximumAggregateInteger: number;
        readonly openingRandomnessAggregateBound: number;
    };
};

const rehashCertificate = (
    certificate: ShareCommitmentMessageBoundCert,
): ShareCommitmentMessageBoundCert => {
    const certificateWithoutDigest: Omit<
        ShareCommitmentMessageBoundCert,
        'shareCommitmentMessageBoundCertDigest'
    > = {
        objectType: certificate.objectType,
        objectVersion: certificate.objectVersion,
        profileId: certificate.profileId,
        profileDigest: certificate.profileDigest,
        shareCommitmentProfileDigest: certificate.shareCommitmentProfileDigest,
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
        ...certificateWithoutDigest,
        shareCommitmentMessageBoundCertDigest:
            deriveShareCommitmentMessageBoundCertDigest(
                certificateWithoutDigest,
            ),
    };
};

describe('ballot privacy profile freeze', () => {
    it('freezes production-shaped profile choices without using transport KEM as receiver encryption', () => {
        const profileSet = createBallotPrivacyProfileSet();
        const profileDigests = deriveBallotPrivacyProfileDigests();

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
            bindsActionContextDigest: true,
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
        expect(profileSet.ballotProofProfile.profileId).toBe(
            ballotPrivacyProfileVector.profileIds.ballotProofProfileId,
        );
        expect(profileSet.ballotProofProfile.fiatShamirModel).toBe(
            'QROMAccountedRequired',
        );
        expect(profileSet.ballotProofProfile.challengeBits).toBe(256);
        expect(profileSet.ballotProofProfile.soundnessBits).toBe(128);
        expect(profileDigests).toEqual(
            ballotPrivacyProfileVector.profileDigests,
        );
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
                expectedShareCommitmentProfileDigest:
                    profileSet.shareCommitmentProfile
                        .shareCommitmentProfileDigest,
            }).ok,
        ).toBe(true);
        expect(
            verifyShareCommitmentMessageBoundCert({
                certificate: certificateGatedCertificate,
                expectedMaximumCanonicalTurnout: 50,
                expectedShareCommitmentProfileDigest:
                    profileSet.shareCommitmentProfile
                        .shareCommitmentProfileDigest,
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
        const wrongDigestCertificate: ShareCommitmentMessageBoundCert = {
            ...certificate,
            shareCommitmentMessageBoundCertDigest: '0'.repeat(128),
        };
        const wrappingCertificate = rehashCertificate({
            ...certificate,
            commitmentMessageBound: String(
                certificate.maximumAggregateInteger - 1,
            ),
        });
        const inconsistentOpeningCertificate = rehashCertificate({
            ...certificate,
            openingRandomnessAggregateBound:
                certificate.openingRandomnessAggregateBound + 1,
        });

        expect(
            verifyShareCommitmentMessageBoundCert({
                certificate: wrongDigestCertificate,
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
                expectedShareCommitmentProfileDigest: '1'.repeat(128),
            }).refusedObjects.map((refusal) => refusal.message),
        ).toContain(
            'Share commitment message-bound certificate is not bound to the expected share commitment profile.',
        );
    });

    it('reserves every ballot privacy digest namespace in the shared registry', () => {
        expect(protocolDigestNamespaceValues).toEqual(
            expect.arrayContaining([
                'ReceiverEncryptionProfileDigest',
                'ShareCommitmentProfileDigest',
                'BallotProofProfileDigest',
                'ScoreMembershipProfileDigest',
                'ShareCommitmentMessageBoundCertDigest',
                'ReceiverPayloadDigest',
                'ReceiverPayloadCiphertextRoot',
                'ReceiverKeyProofRoot',
                'BallotProofStatementDigest',
                'BallotProofRecordDigest',
                'ChallengeDomainDigest',
            ]),
        );
    });
});
