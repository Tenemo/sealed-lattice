import { describe, expect, it } from 'vitest';

import {
    certificationReleaseThresholdTrace,
    compileCertificationReleaseThresholdCensus,
} from '#tests/certification-release-threshold-model.js';

describe('combining target votes with ordinary release shares', () => {
    it('reconstructs from private corrupt shares before a public target certificate', () => {
        const trace = certificationReleaseThresholdTrace(10, 7);
        expect(trace.recovered).toBe(73);
        expect(trace.corruptPrivateShares).toHaveLength(3);
        expect(trace.honestPublicShares).toHaveLength(4);
        expect(trace.publicCertificateAvailable).toBe(false);
        expect(trace.everyContinuingSetCanDecrypt).toBe(true);
    });

    it('cannot repair both properties by increasing only the share threshold', () => {
        const census = compileCertificationReleaseThresholdCensus();
        expect(census.minimumThresholdDelayingThisTrace).toBe(10);
        expect(census.maximumThresholdForEveryContinuingSet).toBe(7);
        for (const example of census.cases)
            expect(
                example.publicCertificateAvailable &&
                    example.everyContinuingSetCanDecrypt,
            ).toBe(false);
    });

    it('checks interpolation and the threshold gap across supported fault profiles', () => {
        for (let participants = 4; participants <= 20; participants++) {
            const faults = Math.floor((participants - 1) / 3);
            for (
                let threshold = faults + 1;
                threshold <= participants;
                threshold++
            ) {
                const trace = certificationReleaseThresholdTrace(
                    participants,
                    threshold,
                );
                expect(trace.recovered).toBe(trace.secret);
                expect(trace.publicVoteCount).toBe(threshold - faults);
                expect(
                    trace.publicCertificateAvailable &&
                        trace.everyContinuingSetCanDecrypt,
                ).toBe(false);
            }
        }
    });

    it('refuses thresholds without the stated sharing premise', () => {
        for (const threshold of [0, 3, 11, 4.5, Number.NaN])
            expect(() =>
                certificationReleaseThresholdTrace(10, threshold),
            ).toThrow();
    });
});
