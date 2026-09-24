import { describe, expect, it } from 'vitest';

import {
    compileSetupRandomnessCensus,
    reduceSignedDigitModel,
} from '#tests/setup-randomness-model.js';

describe('setup randomness and bounded integer reduction', () => {
    it('charges all contribution and registration errors in the preparation profile', () => {
        const result = compileSetupRandomnessCensus();
        expect(result.samplesPerContribution).toBe(44n * 65536n + 4096n);
        expect(result.samplesPerPreparation).toBe(10n * (45n * 65536n + 4096n));
        expect(result.encodedThresholdBytes).toBe(127n * 20n);
        expect(result.quantizationBits).toBeGreaterThan(120);
        expect(result.tailExponent).toBe(200n);
        expect(result.preparationSamplingBits).toBe(128);
    });
    it('matches direct centered division across signed carries and both correction outcomes', () => {
        const corrections = new Set<bigint>();
        for (const radix of [8n, 16n])
            for (const leading of [3n, 5n])
                for (const lower of [1n, radix - 1n]) {
                    const modulus = leading * radix + lower;
                    for (
                        let value = -(leading - 1n) * modulus;
                        value <= (leading - 1n) * modulus;
                        value++
                    ) {
                        for (const transferred of [-2n, 0n, 3n]) {
                            const digits = [
                                (value % radix) + transferred * radix,
                                value / radix - transferred,
                            ];
                            const result = reduceSignedDigitModel(
                                digits,
                                radix,
                                modulus,
                            );
                            let expected =
                                ((value % modulus) + modulus) % modulus;
                            if (expected > modulus / 2n) expected -= modulus;
                            expect(result.remainder).toBe(expected);
                            expect(
                                result.remainder + result.quotient * modulus,
                            ).toBe(value);
                            corrections.add(result.correction);
                        }
                    }
                }
        expect(corrections).toEqual(new Set([0n, 1n]));
    });
    it('refuses the first unavailable quotient-correction premise', () => {
        expect(() => reduceSignedDigitModel([0n], 16n, 6n)).toThrow(
            'Invalid reduction',
        );
        expect(() => reduceSignedDigitModel([0n, 9n], 16n, 49n)).toThrow(
            'single-correction',
        );
    });
});
