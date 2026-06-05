import {
    targetDecryptionProfileId,
    type PollSpec,
    targetBoundShareSelectionProfileId,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    deriveFrozenRosterProfile,
    deriveThresholdProfile,
} from '#packages/protocol/src/index';

const dynamicRosterProfileCertificateHash = 'a'.repeat(128);
const invalidDynamicRosterProfileCertificateHash = 'not-a-protocol-hash';
const rosterHash = 'b'.repeat(128);
const casualMicroRosterSizes = [3, 4, 5, 6, 7, 8, 9] as const;
const pollSpec = {
    duplicateBallotPolicy: 'FirstValidBeforeVotingClosedCounts',
    maxRosterSize: 50,
    minRosterSize: 10,
    options: ['Alpha', 'Beta'],
    pollId: 'threshold-profile-test',
    question: 'Choose one',
    rosterPolicy: 'OpenLinkPublicRoster',
    scoreDomain: {
        max: 10,
        min: 1,
        skippedOptionScore: 1,
    },
    smallRosterPolicy: 'ForbidMicroRoster',
    thresholdProfileFamily: 'BalancedDefault',
    tiePolicy: 'HigherScoreThenLowerOptionIndex',
    topOptionCount: 1,
} as const satisfies PollSpec;

const targetBoundShareSelectionProfile = {
    profileId: targetBoundShareSelectionProfileId,
    certificateHash: 'target-bound-certificate-hash',
    targetDecryptionProfileId,
    targetBasisHash: 'target-basis-hash',
    decryptionShareQuorum: 9,
    minimumSharesForInterpolation: 7,
    minimumArrivalsForRobustDecode: 9,
    invalidShareFilteringMode: 'ProofVerifiedSharesOnly',
    selectedShareRule: 'FirstValidSharesInCanonicalBoardOrder',
} as const;
const retiredThresholdDecryptionProfileId =
    'unsupported-target-decryption-profile-v0';

const expectFeasibleThresholds = (rosterSize: number): void => {
    const decryptionThreshold = Math.floor((rosterSize - 1) / 3) + 1;
    const profile = deriveThresholdProfile({
        casualMicroRosterAcknowledged: rosterSize < 10,
        dynamicRosterProfileCertificateHash:
            rosterSize >= 10 && rosterSize !== 10
                ? dynamicRosterProfileCertificateHash
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
        profile.decryptionThreshold,
    );
    expect(profile.decryptionShareQuorum).toBeGreaterThanOrEqual(
        profile.decryptionThreshold,
    );
    expect(profile.maximumRaceShares).toBe(rosterSize);
    expect(profile.setupCompletionQuorum).toBe(rosterSize);
};

describe('election foundation threshold profiles', () => {
    it.each([
        {
            rosterSize: 10,
            privacyCorruptionBound: 3,
            threshold: 4,
            activeFaultBound: 2,
            releaseQuorum: 10,
        },
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
                dynamicRosterProfileCertificateHash:
                    rosterSize === 10
                        ? undefined
                        : dynamicRosterProfileCertificateHash,
                rosterSize,
            });

            expect(profile).toMatchObject({
                rosterSize,
                privacyCorruptionBound,
                decryptionCorruptionBound: privacyCorruptionBound,
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

    it.each([...casualMicroRosterSizes, 10, 11, 16, 20, 21, 30, 40, 50])(
        'keeps threshold feasibility invariants for roster size %d',
        (rosterSize) => {
            expectFeasibleThresholds(rosterSize);
        },
    );

    it('rejects roster sizes below three', () => {
        expect(() => deriveThresholdProfile({ rosterSize: 2 })).toThrow(
            'Roster size must be at least 3.',
        );
    });

    it.each(casualMicroRosterSizes)(
        'requires explicit casual micro-roster acknowledgement for roster size %d',
        (rosterSize) => {
            expect(() => deriveThresholdProfile({ rosterSize })).toThrow(
                'Casual micro-roster profiles require explicit acknowledgement.',
            );
        },
    );

    it.each([
        { rosterSize: 3, threshold: 1 },
        { rosterSize: 4, threshold: 2 },
        { rosterSize: 5, threshold: 2 },
        { rosterSize: 6, threshold: 2 },
        { rosterSize: 7, threshold: 3 },
        { rosterSize: 8, threshold: 3 },
        { rosterSize: 9, threshold: 3 },
    ])(
        'marks acknowledged roster size $rosterSize as a non-claim casual micro-roster',
        ({ rosterSize, threshold }) => {
            const profile = deriveThresholdProfile({
                casualMicroRosterAcknowledged: true,
                rosterSize,
            });

            expect(profile.rosterProfileKind).toBe('CasualMicroRoster');
            expect(profile.claimBoundary).toBe('CasualMicroRoster');
            expect(profile.claimBearing).toBe(false);
            expect(profile.releaseQuorum).toBe(rosterSize);
            expect(profile.setupCompletionQuorum).toBe(rosterSize);
            expect(profile.decryptionThreshold).toBe(threshold);
            expect(profile.warnings).toContain('CasualMicroRoster');
        },
    );

    it('marks roster size 10 as the mandatory benchmark profile', () => {
        const profile = deriveThresholdProfile({ rosterSize: 10 });

        expect(profile.rosterProfileKind).toBe('MandatoryBenchmarkRoster');
        expect(profile.claimBoundary).toBe('MandatoryBenchmark');
        expect(profile.claimBearing).toBe(true);
        expect(profile.dynamicRosterProfileCertificateHash).toBeNull();
        expect(profile.warnings).toEqual(['ShareSelectionProfileRequired']);
    });

    it('keeps mandatory benchmark profiles independent from dynamic roster certificate inputs', () => {
        const baselineProfile = deriveThresholdProfile({ rosterSize: 10 });
        const profileWithCertificate = deriveThresholdProfile({
            dynamicRosterProfileCertificateHash,
            rosterSize: 10,
        });

        expect(profileWithCertificate).toEqual(baselineProfile);

        const baselineFrozenRosterProfile = deriveFrozenRosterProfile({
            pollSpec,
            rosterHash,
            rosterSize: 10,
        });
        const frozenRosterProfileWithCertificate = deriveFrozenRosterProfile({
            dynamicRosterProfileCertificateHash,
            pollSpec,
            rosterHash,
            rosterSize: 10,
        });

        expect(frozenRosterProfileWithCertificate).toEqual(
            baselineFrozenRosterProfile,
        );
    });

    it('does not carry invalid dynamic roster certificate hashes into mandatory benchmark profiles', () => {
        const profile = deriveThresholdProfile({
            dynamicRosterProfileCertificateHash:
                invalidDynamicRosterProfileCertificateHash,
            rosterSize: 10,
        });

        expect(profile.rosterProfileKind).toBe('MandatoryBenchmarkRoster');
        expect(profile.claimBoundary).toBe('MandatoryBenchmark');
        expect(profile.claimBearing).toBe(true);
        expect(profile.dynamicRosterProfileCertificateHash).toBeNull();

        const frozenRosterProfile = deriveFrozenRosterProfile({
            dynamicRosterProfileCertificateHash:
                invalidDynamicRosterProfileCertificateHash,
            pollSpec,
            rosterHash,
            rosterSize: 10,
        });

        expect(
            frozenRosterProfile.dynamicRosterProfileCertificateHash,
        ).toBeNull();
        expect(
            frozenRosterProfile.thresholdProfile
                .dynamicRosterProfileCertificateHash,
        ).toBeNull();
        expect(() =>
            deriveFrozenRosterProfile({
                dynamicRosterProfileCertificateHash:
                    invalidDynamicRosterProfileCertificateHash,
                pollSpec,
                rosterHash,
                rosterSize: 20,
            }),
        ).toThrow(
            'Dynamic claim-bearing roster profiles require parameter certificate coverage for the frozen roster size.',
        );
    });

    it.each([11, 16, 20, 21, 50])(
        'marks roster size %d as a certified dynamic profile',
        (rosterSize) => {
            const profile = deriveThresholdProfile({
                dynamicRosterProfileCertificateHash,
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

    it.each([11, 16, 19, 20, 21, 50])(
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
            dynamicRosterProfileCertificateHash,
            rosterSize: 20,
            heBackendCorruptionModel: {
                kind: 'CertifiedCustom',
                backendCorruptionBound: 8,
                certificateHash: 'certified-profile-hash',
            },
        });

        expect(profile.structuralCorruptionBound).toBe(6);
        expect(profile.backendCorruptionBound).toBe(8);
        expect(profile.privacyCorruptionBound).toBe(6);
        expect(profile.warnings).toContain('BackendCorruptionBoundTooHigh');
    });

    it('uses target-bound share-selection output for decryption share quorum', () => {
        const profile = deriveThresholdProfile({
            dynamicRosterProfileCertificateHash,
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
                dynamicRosterProfileCertificateHash,
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
                dynamicRosterProfileCertificateHash,
                rosterSize: 20,
                targetBoundShareSelectionProfile: {
                    ...targetBoundShareSelectionProfile,
                    targetDecryptionProfileId: 'arbitrary-target-profile',
                },
            }),
        ).toThrow(
            'Target-bound share-selection profile uses an unsupported target decryption profile ID.',
        );
        expect(() =>
            deriveThresholdProfile({
                dynamicRosterProfileCertificateHash,
                rosterSize: 20,
                targetBoundShareSelectionProfile: {
                    ...targetBoundShareSelectionProfile,
                    targetDecryptionProfileId:
                        retiredThresholdDecryptionProfileId,
                },
            }),
        ).toThrow(
            'Target-bound share-selection profile uses an unsupported target decryption profile ID.',
        );

        expect(() =>
            deriveThresholdProfile({
                dynamicRosterProfileCertificateHash,
                rosterSize: 20,
                targetBoundShareSelectionProfile: {
                    ...targetBoundShareSelectionProfile,
                    targetBasisHash: '',
                },
            }),
        ).toThrow(
            'Target-bound share-selection profile requires a target-basis hash.',
        );
    });

    it('rejects target-bound share-selection profiles that cannot certify safe recombination', () => {
        expect(() =>
            deriveThresholdProfile({
                dynamicRosterProfileCertificateHash,
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
                dynamicRosterProfileCertificateHash,
                rosterSize: 20,
                targetBoundShareSelectionProfile: {
                    ...targetBoundShareSelectionProfile,
                    certificateHash: '',
                },
            }),
        ).toThrow(
            'Target-bound share-selection profile requires a certificate hash.',
        );

        expect(() =>
            deriveThresholdProfile({
                dynamicRosterProfileCertificateHash,
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
