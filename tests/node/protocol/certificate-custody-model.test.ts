import { describe, expect, it } from 'vitest';

import {
    compileCertificateCustodyCensus,
    fullHolderRequirements,
    runCertificateCustodyCounterexample,
} from '#tests/certificate-custody-model.js';

describe('certificate custody after disappearance', () => {
    it('distinguishes a quorum of signers from a recoverable complete certificate', () => {
        const stalled = runCertificateCustodyCounterexample(false);
        expect(stalled.fullCertificateExisted).toBe(true);
        expect(stalled.continuingHonestParticipants).toBe(4);
        expect(stalled.recoverableSignatures).toBe(4);
        expect(stalled.canRecoverCertificate).toBe(false);
        const delivered = runCertificateCustodyCounterexample(true);
        expect(delivered.recoverableSignatures).toBe(7);
        expect(delivered.canRecoverCertificate).toBe(true);
    });

    it('checks every named corruption, disappearance, and full-holder set', () => {
        const census = compileCertificateCustodyCensus();
        // C(10,3)=120 choices for each unavailable set and each complement
        // of a seven-position full-holder set.
        expect(census.checkedConfigurations).toBe(120 ** 3);
        expect(census.minimumSurvivingHonestFullHolders).toBe(
            census.fullHolderThreshold - 2 * census.corruptCount,
        );
        expect(census.minimumSurvivingHonestFullHolders).toBe(1);
    });

    it('derives distinct full-copy and coded-retention holder requirements', () => {
        expect(fullHolderRequirements(10, 3, 3, 1)).toEqual({
            requiredHolders: 7,
            possible: true,
        });
        expect(fullHolderRequirements(10, 3, 3, 4)).toEqual({
            requiredHolders: 10,
            possible: true,
        });
        expect(fullHolderRequirements(10, 3, 3, 5)).toEqual({
            requiredHolders: 11,
            possible: false,
        });
        for (const values of [
            [10, 3, 3, 0],
            [0, 0, 0, 1],
            [10, -1, 3, 1],
            [10, 3, 1.5, 1],
        ])
            expect(() =>
                fullHolderRequirements(
                    values[0],
                    values[1],
                    values[2],
                    values[3],
                ),
            ).toThrow(RangeError);
        // Independent named-set enumeration permits overlapping corruption and
        // departure sets and finds the worst case when their losses are disjoint.
        for (const holders of [7, 10]) {
            let minimumSurvivors = 10;
            const triples: number[][] = [];
            for (let first = 0; first < 10; first++)
                for (let second = first + 1; second < 10; second++)
                    for (let third = second + 1; third < 10; third++)
                        triples.push([first, second, third]);
            for (const corrupt of triples)
                for (const departed of triples) {
                    const surviving = Array.from(
                        { length: holders },
                        (_, i) => i,
                    ).filter(
                        (position) =>
                            !corrupt.includes(position) &&
                            !departed.includes(position),
                    );
                    minimumSurvivors = Math.min(
                        minimumSurvivors,
                        surviving.length,
                    );
                }
            expect(minimumSurvivors).toBe(holders === 7 ? 1 : 4);
        }
    });
});
