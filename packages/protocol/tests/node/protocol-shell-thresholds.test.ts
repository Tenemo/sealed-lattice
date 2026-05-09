import { describe, expect, it } from 'vitest';

import { deriveThresholdProfile } from '../../src/protocol-shell/index';

const expectFeasibleThresholds = (n: number): void => {
    const profile = deriveThresholdProfile({
        n,
        unsafeMicroRosterAcknowledged: n < 20,
    });

    expect(n - profile.fAct).toBeGreaterThanOrEqual(profile.tPvss);
    expect(n - profile.fAct).toBeGreaterThanOrEqual(profile.qEval);
    expect(n - profile.fAct).toBeGreaterThanOrEqual(profile.tDec);
    expect(profile.qAgg).toBe(profile.tPvss);
    expect(profile.qDec).toBe(profile.tDec);
    expect(profile.raceShareMax).toBe(n);
    expect(profile.qSetupComplete).toBe(n);
};

describe('protocol-shell threshold profiles', () => {
    it.each([
        { n: 20, cPriv: 6, threshold: 7, fAct: 4, qEval: 5, qRelease: 14 },
        { n: 30, cPriv: 9, threshold: 10, fAct: 6, qEval: 7, qRelease: 20 },
        { n: 40, cPriv: 13, threshold: 14, fAct: 8, qEval: 9, qRelease: 27 },
        { n: 50, cPriv: 16, threshold: 17, fAct: 10, qEval: 11, qRelease: 34 },
    ])(
        'derives strict less-than-one-third thresholds for n=$n',
        ({ n, cPriv, threshold, fAct, qEval, qRelease }) => {
            const profile = deriveThresholdProfile({ n });

            expect(profile).toMatchObject({
                n,
                cPriv,
                cDec: cPriv,
                tPvss: threshold,
                tDec: threshold,
                fAct,
                qEval,
                qRelease,
            });
        },
    );

    it('keeps n=30 at cPriv=9 under strict less-than-one-third', () => {
        expect(deriveThresholdProfile({ n: 30 }).cPriv).toBe(9);
    });

    it.each([20, 30, 40, 50])(
        'keeps threshold feasibility invariants for n=%d',
        expectFeasibleThresholds,
    );

    it('rejects roster sizes below three', () => {
        expect(() => deriveThresholdProfile({ n: 2 })).toThrow(
            'Roster size must be at least 3.',
        );
    });

    it.each([3, 19])(
        'requires explicit unsafe acknowledgement for n=%d',
        (n) => {
            expect(() => deriveThresholdProfile({ n })).toThrow(
                'Unsafe micro-roster profiles require explicit acknowledgement.',
            );
        },
    );

    it('marks acknowledged micro-rosters as non-claim-bearing', () => {
        const profile = deriveThresholdProfile({
            n: 19,
            unsafeMicroRosterAcknowledged: true,
        });

        expect(profile.rosterProfileKind).toBe('UnsafeMicroRoster');
        expect(profile.claimBearing).toBe(false);
        expect(profile.warnings).toContain('UnsafeMicroRoster');
    });

    it('marks n=20 as the mandatory claim-bearing profile', () => {
        const profile = deriveThresholdProfile({ n: 20 });

        expect(profile.rosterProfileKind).toBe('MandatoryN20');
        expect(profile.claimBearing).toBe(true);
        expect(profile.warnings).toEqual([]);
    });

    it.each([21, 50])(
        'marks n=%d as certificate-gated in protocol shell',
        (n) => {
            const profile = deriveThresholdProfile({ n });

            expect(profile.rosterProfileKind).toBe('CertificateGatedRange');
            expect(profile.claimBearing).toBe(false);
            expect(profile.warnings).toEqual([
                'CertificateGatedProfile',
                'BackendCertificateRequired',
            ]);
        },
    );

    it('rejects roster sizes above fifty', () => {
        expect(() => deriveThresholdProfile({ n: 51 })).toThrow(
            'Roster size must be at most 50.',
        );
    });

    it('warns when a certified backend bound exceeds the structural bound', () => {
        const profile = deriveThresholdProfile({
            n: 20,
            heBackendCorruptionModel: {
                kind: 'CertifiedCustom',
                cHeBackend: 8,
                certificateDigest: 'certified-profile-digest',
            },
        });

        expect(profile.cStruct).toBe(6);
        expect(profile.cHeBackend).toBe(8);
        expect(profile.cPriv).toBe(6);
        expect(profile.warnings).toContain('BackendCorruptionBoundTooHigh');
    });
});
