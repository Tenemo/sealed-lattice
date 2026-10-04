import { describe, expect, it } from 'vitest';

import { compileRegistrationSetupBindingScreen } from '#tests/registration-setup-binding-model.js';
import {
    compileSetupRandomnessCensus,
    reduceSignedDigitModel,
} from '#tests/setup-randomness-model.js';
import { completionProfile } from '#tests/supported-profile-model.js';

describe('setup randomness and bounded integer reduction', () => {
    it('charges all contribution and registration errors in the preparation profile', () => {
        const result = compileSetupRandomnessCensus(completionProfile());
        const families = compileRegistrationSetupBindingScreen(
            10,
            10,
        ).coordinateCount;
        expect(result.samplesPerContribution).toBe(43n * 65536n);
        expect(result.samplesPerSourceFamily).toBe(65536n);
        expect(result.samplesPerEnrollment).toBe((1n + families) * 65536n);
        // Four contributors reuse their original first error. Every
        // registrant generated all families, including unselected ones.
        expect(result.samplesPerPreparation).toBe(
            4n * 43n * 65536n + 10n * (1n + families) * 65536n,
        );
        expect(result.encodedThresholdBytes).toBe(127n * 20n);
        expect(result.quantizationBits).toBeGreaterThan(120);
        expect(result.tailExponent).toBe(200n);
        expect(result.preparationSamplingBits).toBe(
            (
                result.preparationVariationDenominator /
                result.preparationVariationNumerator
            ).toString(2).length - 1,
        );
    });
    it('keeps the original poll maximum independent from its final roster', () => {
        const profile = completionProfile();
        const small = compileSetupRandomnessCensus(profile);
        const larger = compileSetupRandomnessCensus(profile, 20);
        const families = compileRegistrationSetupBindingScreen(
            20,
            10,
        ).coordinateCount;
        expect(larger.originalPollMaximumParticipants).toBe(20);
        expect(larger.sourceFamilyCount).toBe(families);
        expect(larger.samplesPerContribution).toBe(
            small.samplesPerContribution,
        );
        expect(larger.samplesPerPreparation - small.samplesPerPreparation).toBe(
            10n * 65536n * (families - small.sourceFamilyCount),
        );
        expect(() => compileSetupRandomnessCensus(profile, 9)).toThrow(
            'exclude',
        );
        expect(() => compileSetupRandomnessCensus(profile, 21)).toThrow();
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
