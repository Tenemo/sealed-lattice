import {
    cpadProfileId,
    targetBoundShareSelectionProfileId,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import { deriveThresholdProfile } from '../../src/index';

const dynamicRosterProfileCertificateDigest = 'a'.repeat(128);

const targetBoundShareSelectionProfile = {
    profileId: targetBoundShareSelectionProfileId,
    certificateDigest: 'target-bound-certificate-digest',
    cpadProfileId,
    targetBasisDigest: 'target-basis-digest',
    decryptionShareQuorum: 9,
    minimumSharesForInterpolation: 7,
    minimumArrivalsForRobustDecode: 9,
    invalidShareFilteringMode: 'ProofVerifiedSharesOnly',
    selectedShareRule: 'FirstValidSharesInCanonicalBoardOrder',
} as const;

const expectFeasibleThresholds = (rosterSize: number): void => {
    const decryptionThreshold = Math.floor((rosterSize - 1) / 3) + 1;
    const profile = deriveThresholdProfile({
        casualMicroRosterAcknowledged: rosterSize < 10,
        dynamicRosterProfileCertificateDigest:
            rosterSize >= 10 && rosterSize !== 20
                ? dynamicRosterProfileCertificateDigest
                : undefined,
        rosterSize,
        targetBoundShareSelectionProfile: {
            ...targetBoundShareSelectionProfile,
            decryptionShareQuorum: decryptionThreshold + 2,
            minimumSharesForInterpolation: decryptionThreshold,
            minimumArrivalsForRobustDecode: decryptionThreshold + 2,
        },
    });

    expect(rosterSize - profile.activeFaultBound).toBeGreaterThanOrEqual(
        profile.pvssThreshold,
    );
    expect(rosterSize - profile.activeFaultBound).toBeGreaterThanOrEqual(
        profile.decryptionThreshold,
    );
    expect(profile.aggregateContributionQuorum).toBe(profile.pvssThreshold);
    expect(profile.decryptionShareQuorum).toBeGreaterThanOrEqual(
        profile.decryptionThreshold,
    );
    expect(profile.maximumRaceShares).toBe(rosterSize);
    expect(profile.setupCompletionQuorum).toBe(rosterSize);
};

describe('election foundation threshold profiles', () => {
    it.each([
        {
            rosterSize: 11,
            privacyCorruptionBound: 3,
            threshold: 4,
            activeFaultBound: 2,
            releaseQuorum: 10,
        },
        {
            rosterSize: 16,
            privacyCorruptionBound: 5,
            threshold: 6,
            activeFaultBound: 3,
            releaseQuorum: 11,
        },
        {
            rosterSize: 20,
            privacyCorruptionBound: 6,
            threshold: 7,
            activeFaultBound: 4,
            releaseQuorum: 14,
        },
        {
            rosterSize: 21,
            privacyCorruptionBound: 6,
            threshold: 7,
            activeFaultBound: 4,
            releaseQuorum: 14,
        },
        {
            rosterSize: 30,
            privacyCorruptionBound: 9,
            threshold: 10,
            activeFaultBound: 6,
            releaseQuorum: 20,
        },
        {
            rosterSize: 40,
            privacyCorruptionBound: 13,
            threshold: 14,
            activeFaultBound: 8,
            releaseQuorum: 27,
        },
        {
            rosterSize: 50,
            privacyCorruptionBound: 16,
            threshold: 17,
            activeFaultBound: 10,
            releaseQuorum: 34,
        },
    ])(
        'derives strict less-than-one-third thresholds for roster size $rosterSize',
        ({
            rosterSize,
            privacyCorruptionBound,
            threshold,
            activeFaultBound,
            releaseQuorum,
        }) => {
            const profile = deriveThresholdProfile({
                dynamicRosterProfileCertificateDigest:
                    rosterSize === 20
                        ? undefined
                        : dynamicRosterProfileCertificateDigest,
                rosterSize,
            });

            expect(profile).toMatchObject({
                rosterSize,
                privacyCorruptionBound,
                decryptionCorruptionBound: privacyCorruptionBound,
                pvssThreshold: threshold,
                decryptionThreshold: threshold,
                decryptionShareQuorum: null,
                targetBoundShareSelectionProfile: null,
                activeFaultBound,
                releaseQuorum,
            });
            expect(profile.warnings).toContain('ShareSelectionProfileRequired');
        },
    );

    it('keeps roster size 30 at privacy corruption bound 9 under strict less-than-one-third', () => {
        expect(
            deriveThresholdProfile({ rosterSize: 30 }).privacyCorruptionBound,
        ).toBe(9);
    });

    it.each([10, 11, 16, 20, 21, 30, 40, 50])(
        'keeps threshold feasibility invariants for roster size %d',
        expectFeasibleThresholds,
    );

    it('rejects roster sizes below three', () => {
        expect(() => deriveThresholdProfile({ rosterSize: 2 })).toThrow(
            'Roster size must be at least 3.',
        );
    });

    it.each([3, 9])(
        'requires explicit casual micro-roster acknowledgement for roster size %d',
        (rosterSize) => {
            expect(() => deriveThresholdProfile({ rosterSize })).toThrow(
                'Casual micro-roster profiles require explicit acknowledgement.',
            );
        },
    );

    it('marks acknowledged micro rosters as casual and not claim-bearing', () => {
        const profile = deriveThresholdProfile({
            casualMicroRosterAcknowledged: true,
            rosterSize: 9,
        });

        expect(profile.rosterProfileKind).toBe('CasualMicroRoster');
        expect(profile.claimBoundary).toBe('CasualMicroRoster');
        expect(profile.claimBearing).toBe(false);
        expect(profile.warnings).toContain('CasualMicroRoster');
    });

    it('marks roster size 20 as the mandatory benchmark profile', () => {
        const profile = deriveThresholdProfile({ rosterSize: 20 });

        expect(profile.rosterProfileKind).toBe('MandatoryBenchmarkRoster');
        expect(profile.claimBoundary).toBe('MandatoryBenchmark');
        expect(profile.claimBearing).toBe(true);
        expect(profile.warnings).toEqual(['ShareSelectionProfileRequired']);
    });

    it.each([10, 11, 16, 21, 50])(
        'marks roster size %d as a certified dynamic profile',
        (rosterSize) => {
            const profile = deriveThresholdProfile({
                dynamicRosterProfileCertificateDigest,
                rosterSize,
            });

            expect(profile.rosterProfileKind).toBe(
                'SupportedDynamicRosterRange',
            );
            expect(profile.claimBoundary).toBe('DynamicRosterCertificate');
            expect(profile.claimBearing).toBe(true);
            expect(profile.warnings).toEqual(['ShareSelectionProfileRequired']);
        },
    );

    it.each([10, 11, 16, 19, 21, 50])(
        'marks roster size %d as uncertified without dynamic evidence',
        (rosterSize) => {
            const profile = deriveThresholdProfile({ rosterSize });

            expect(profile.rosterProfileKind).toBe('UncertifiedDynamicRoster');
            expect(profile.claimBoundary).toBe(
                'DynamicRosterCertificateMissing',
            );
            expect(profile.claimBearing).toBe(false);
            expect(profile.warnings).toEqual([
                'DynamicRosterProfileCertificateRequired',
                'ShareSelectionProfileRequired',
            ]);
        },
    );

    it('rejects roster sizes above fifty', () => {
        expect(() => deriveThresholdProfile({ rosterSize: 51 })).toThrow(
            'Roster size must be at most 50.',
        );
    });

    it('warns when a certified backend bound exceeds the structural bound', () => {
        const profile = deriveThresholdProfile({
            rosterSize: 20,
            heBackendCorruptionModel: {
                kind: 'CertifiedCustom',
                backendCorruptionBound: 8,
                certificateDigest: 'certified-profile-digest',
            },
        });

        expect(profile.structuralCorruptionBound).toBe(6);
        expect(profile.backendCorruptionBound).toBe(8);
        expect(profile.privacyCorruptionBound).toBe(6);
        expect(profile.warnings).toContain('BackendCorruptionBoundTooHigh');
    });

    it('uses target-bound share-selection output for decryption share quorum', () => {
        const profile = deriveThresholdProfile({
            rosterSize: 20,
            targetBoundShareSelectionProfile,
        });

        expect(profile.decryptionThreshold).toBe(7);
        expect(profile.decryptionShareQuorum).toBe(9);
        expect(profile.targetBoundShareSelectionProfile).toEqual(
            targetBoundShareSelectionProfile,
        );
        expect(profile.warnings).not.toContain('ShareSelectionProfileRequired');
    });

    it('rejects unsupported target-bound share-selection profile and target-basis bindings', () => {
        expect(() =>
            deriveThresholdProfile({
                rosterSize: 20,
                targetBoundShareSelectionProfile: {
                    ...targetBoundShareSelectionProfile,
                    profileId: 'arbitrary-profile',
                },
            }),
        ).toThrow(
            'Target-bound share-selection profile uses an unsupported ID.',
        );

        expect(() =>
            deriveThresholdProfile({
                rosterSize: 20,
                targetBoundShareSelectionProfile: {
                    ...targetBoundShareSelectionProfile,
                    cpadProfileId: 'arbitrary-cpad-profile',
                },
            }),
        ).toThrow(
            'Target-bound share-selection profile uses an unsupported CPAD profile ID.',
        );

        expect(() =>
            deriveThresholdProfile({
                rosterSize: 20,
                targetBoundShareSelectionProfile: {
                    ...targetBoundShareSelectionProfile,
                    targetBasisDigest: '',
                },
            }),
        ).toThrow(
            'Target-bound share-selection profile requires a target-basis digest.',
        );
    });

    it('rejects target-bound share-selection profiles that cannot certify safe recombination', () => {
        expect(() =>
            deriveThresholdProfile({
                rosterSize: 20,
                targetBoundShareSelectionProfile: {
                    ...targetBoundShareSelectionProfile,
                    decryptionShareQuorum: 6,
                },
            }),
        ).toThrow(
            'Target-bound decryption share quorum must be at least the decryption threshold.',
        );

        expect(() =>
            deriveThresholdProfile({
                rosterSize: 20,
                targetBoundShareSelectionProfile: {
                    ...targetBoundShareSelectionProfile,
                    certificateDigest: '',
                },
            }),
        ).toThrow(
            'Target-bound share-selection profile requires a certificate digest.',
        );

        expect(() =>
            deriveThresholdProfile({
                rosterSize: 20,
                targetBoundShareSelectionProfile: {
                    ...targetBoundShareSelectionProfile,
                    minimumArrivalsForRobustDecode: 8,
                },
            }),
        ).toThrow(
            'Target-bound robust-decode arrival count must be at least the decryption share quorum.',
        );
    });
});
