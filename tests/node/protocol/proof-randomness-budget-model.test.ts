import { describe, expect, it } from 'vitest';

import { compileRegistrationWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import {
    bufferedFieldSamplingFailure,
    compileProofRandomnessBudgets,
} from '#tests/proof-randomness-budget-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';

describe('bounded randomness for complete proof simulation', () => {
    it('matches the independently encoded registration proof shape', () => {
        expect(
            compileRegistrationWordProofLayout().maximumMultiproofBytes,
        ).toBe(compileRegistrationKeyRelationCensus().maximumProofBytes);
    });

    it('bounds exact small-field rejection events without assuming independent stopping positions', () => {
        // Exhaust all three-byte tapes for a sampler accepting 255 values.
        // At least two rejections is the union of the three index pairs.
        const bound = bufferedFieldSamplingFailure({
            baselineBytes: 2n,
            bufferBytes: 1n,
            sampleBits: 8n,
            modulus: 255n,
            extraReads: 1n,
            invocations: 1n,
        });
        let failures = 0n;
        for (let first = 0; first < 256; first++)
            for (let second = 0; second < 256; second++)
                for (let third = 0; third < 256; third++)
                    failures += BigInt(
                        Number(first === 255) +
                            Number(second === 255) +
                            Number(third === 255) >=
                            2,
                    );
        expect(failures).toBe(766n);
        expect(failures * (1n << bound.denominatorBits)).toBeLessThanOrEqual(
            bound.numerator * 256n ** 3n,
        );
    });

    it('charges the complete role population and only adds enough read headroom', () => {
        const budgets = compileProofRandomnessBudgets();
        expect(budgets.map((value) => value.role)).toEqual([
            'registration',
            'setup contribution',
            'linked ballot',
            'linked release',
        ]);
        for (const value of budgets) {
            expect(value.simulatorBaselineBytes).toBe(
                value.ordinaryBaselineBytes + 262_144n,
            );
            expect(value.failure.numerator << 128n).toBeLessThanOrEqual(
                1n << value.failure.denominatorBits,
            );
            expect(value.invocationCap).toBe(65_536n);
            expect(value.extraReads).toBeGreaterThan(0n);
            const previousPositions =
                (value.simulatorBaselineBytes +
                    (value.extraReads - 1n) * 65_536n) /
                16n;
            let pairs = 1n;
            for (let index = 1n; index <= value.extraReads; index++)
                pairs = (pairs * (previousPositions - index + 1n)) / index;
            const rejectedWords = 133n * (1n << 64n) - 1n;
            expect(
                (65_536n * pairs * rejectedWords ** value.extraReads) << 128n,
            ).toBeGreaterThan(1n << (128n * value.extraReads));
        }
    });

    it('refuses misaligned budgets and accounts for a rejection-free alphabet', () => {
        const input = {
            baselineBytes: 32n,
            bufferBytes: 16n,
            sampleBits: 128n,
            modulus: 1n << 128n,
            extraReads: 0n,
            invocations: 1n,
        };
        expect(bufferedFieldSamplingFailure(input).numerator).toBe(0n);
        expect(() =>
            bufferedFieldSamplingFailure({ ...input, baselineBytes: 33n }),
        ).toThrow('Invalid');
        expect(() =>
            bufferedFieldSamplingFailure({ ...input, invocations: 0n }),
        ).toThrow('Invalid');
    });
});
