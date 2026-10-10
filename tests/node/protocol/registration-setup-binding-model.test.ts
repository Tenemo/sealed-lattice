import { describe, expect, it } from 'vitest';

import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileBoundedKeyUniqueness } from '#tests/recipient-key-uniqueness-model.js';
import { compileRegistrationSetupBindingScreen } from '#tests/registration-setup-binding-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';

describe('registration-bound setup key screen', () => {
    it.each([
        [3, 2],
        [10, 10],
        [20, 20],
    ])(
        'covers every possible roster up to %i with %i options',
        (maximum, options) => {
            const screen = compileRegistrationSetupBindingScreen(
                maximum,
                options,
            );
            expect(
                screen.fhe
                    .flatMap((family) => family.profiles)
                    .sort((a, b) => a - b),
            ).toEqual(
                Array.from(
                    { length: maximum - 2 },
                    (_unused, index) => index + 3,
                ),
            );
            for (const family of screen.fhe) {
                for (const participants of family.profiles)
                    expect(family.modulus).toBe(
                        deriveSupportedProfile(participants, options).ciphertext
                            .modulus,
                    );
                const bits = family.modulus.toString(2).length;
                expect(family.publicCoordinateBytes).toBe(
                    fixedModulusBfvInputs.polynomialDegree *
                        BigInt(1 + Math.ceil(bits / 8)),
                );
                expect(
                    family.uniqueness.uniformMatrixFailureExponent,
                ).toBeGreaterThan(128n);
            }
            expect(2n * screen.auxiliary.goodKeyPhaseError).toBeLessThan(
                screen.auxiliary.scale,
            );
            expect(
                screen.generatedPublicCoordinateBytes,
            ).toBeGreaterThanOrEqual(screen.largestPublicCoordinateBytes);
        },
    );

    it('does not reuse one final-size modulus for smaller rosters', () => {
        const screen = compileRegistrationSetupBindingScreen(10, 10);
        expect(
            new Set(screen.fhe.map((family) => family.modulus)).size,
        ).toBeGreaterThan(1);
        expect(screen.fhe[0].modulus).not.toBe(
            screen.fhe[screen.fhe.length - 1].modulus,
        );
    });

    it('checks the determinant-bound operands independently at a small split prime', () => {
        const result = compileBoundedKeyUniqueness(2n, 65537n, 1n, 2n);
        // (5 * 9 * 2 * sqrt(2))^2; the square removes rounding.
        expect(result.squaredFailureBaseNumerator).toBe(16_200n);
        expect(result.uniformMatrixFailureExponent).toBe(18n);
        expect(16_200n * (1n << 18n)).toBeLessThanOrEqual(65537n ** 2n);
        expect(16_200n * (1n << 20n)).toBeGreaterThan(65537n ** 2n);
        expect(() => compileBoundedKeyUniqueness(3n, 65537n, 1n, 2n)).toThrow(
            'cyclotomic',
        );
        expect(() => compileBoundedKeyUniqueness(2n, 7n, 1n, 2n)).toThrow(
            'cyclotomic',
        );
    });
});
