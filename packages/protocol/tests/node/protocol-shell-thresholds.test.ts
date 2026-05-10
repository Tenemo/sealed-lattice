import { describe, expect, it } from 'vitest';

import { deriveThresholdProfile } from '../../src/protocol-shell/index';

const expectFeasibleThresholds = (rosterSize: number): void => {
    const profile = deriveThresholdProfile({
        rosterSize,
        unsafeMicroRosterAcknowledged: rosterSize < 20,
    });

    expect(rosterSize - profile.activeFaultBound).toBeGreaterThanOrEqual(
        profile.pvssThreshold,
    );
    expect(rosterSize - profile.activeFaultBound).toBeGreaterThanOrEqual(
        profile.evaluationReplayQuorum,
    );
    expect(rosterSize - profile.activeFaultBound).toBeGreaterThanOrEqual(
        profile.decryptionThreshold,
    );
    expect(profile.aggregateContributionQuorum).toBe(profile.pvssThreshold);
    expect(profile.decryptionShareQuorum).toBe(profile.decryptionThreshold);
    expect(profile.replayBadCorruptionBound).toBe(profile.activeFaultBound);
    expect(profile.evaluationReplayQuorum).toBe(
        profile.replayBadCorruptionBound + 1,
    );
    expect(profile.maximumRaceShares).toBe(rosterSize);
    expect(profile.setupCompletionQuorum).toBe(rosterSize);
};

describe('protocol-shell threshold profiles', () => {
    it.each([
        {
            rosterSize: 20,
            privacyCorruptionBound: 6,
            threshold: 7,
            activeFaultBound: 4,
            evaluationReplayQuorum: 5,
            releaseQuorum: 14,
        },
        {
            rosterSize: 30,
            privacyCorruptionBound: 9,
            threshold: 10,
            activeFaultBound: 6,
            evaluationReplayQuorum: 7,
            releaseQuorum: 20,
        },
        {
            rosterSize: 40,
            privacyCorruptionBound: 13,
            threshold: 14,
            activeFaultBound: 8,
            evaluationReplayQuorum: 9,
            releaseQuorum: 27,
        },
        {
            rosterSize: 50,
            privacyCorruptionBound: 16,
            threshold: 17,
            activeFaultBound: 10,
            evaluationReplayQuorum: 11,
            releaseQuorum: 34,
        },
    ])(
        'derives strict less-than-one-third thresholds for roster size $rosterSize',
        ({
            rosterSize,
            privacyCorruptionBound,
            threshold,
            activeFaultBound,
            evaluationReplayQuorum,
            releaseQuorum,
        }) => {
            const profile = deriveThresholdProfile({ rosterSize });

            expect(profile).toMatchObject({
                rosterSize,
                privacyCorruptionBound,
                decryptionCorruptionBound: privacyCorruptionBound,
                replayBadCorruptionBound: activeFaultBound,
                pvssThreshold: threshold,
                decryptionThreshold: threshold,
                activeFaultBound,
                evaluationReplayQuorum,
                releaseQuorum,
            });
        },
    );

    it('keeps roster size 30 at privacy corruption bound 9 under strict less-than-one-third', () => {
        expect(
            deriveThresholdProfile({ rosterSize: 30 }).privacyCorruptionBound,
        ).toBe(9);
    });

    it.each([20, 30, 40, 50])(
        'keeps threshold feasibility invariants for roster size %d',
        expectFeasibleThresholds,
    );

    it('rejects roster sizes below three', () => {
        expect(() => deriveThresholdProfile({ rosterSize: 2 })).toThrow(
            'Roster size must be at least 3.',
        );
    });

    it.each([3, 19])(
        'requires explicit unsafe acknowledgement for roster size %d',
        (rosterSize) => {
            expect(() => deriveThresholdProfile({ rosterSize })).toThrow(
                'Unsafe micro-roster profiles require explicit acknowledgement.',
            );
        },
    );

    it('marks acknowledged micro-rosters as non-claim-bearing', () => {
        const profile = deriveThresholdProfile({
            rosterSize: 19,
            unsafeMicroRosterAcknowledged: true,
        });

        expect(profile.rosterProfileKind).toBe('UnsafeMicroRoster');
        expect(profile.claimBearing).toBe(false);
        expect(profile.warnings).toContain('UnsafeMicroRoster');
    });

    it('marks roster size 20 as the mandatory claim-bearing profile', () => {
        const profile = deriveThresholdProfile({ rosterSize: 20 });

        expect(profile.rosterProfileKind).toBe('MandatoryN20');
        expect(profile.claimBearing).toBe(true);
        expect(profile.warnings).toEqual([]);
    });

    it.each([21, 50])(
        'marks roster size %d as certificate-gated in protocol shell',
        (rosterSize) => {
            const profile = deriveThresholdProfile({ rosterSize });

            expect(profile.rosterProfileKind).toBe('CertificateGatedRange');
            expect(profile.claimBearing).toBe(false);
            expect(profile.warnings).toEqual([
                'CertificateGatedProfile',
                'BackendCertificateRequired',
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
});
