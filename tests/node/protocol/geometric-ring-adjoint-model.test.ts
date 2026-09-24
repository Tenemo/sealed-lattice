import { describe, expect, it } from 'vitest';

import {
    fingerprintSignedLimbs,
    geometricNegacyclicAdjoint,
} from '#tests/geometric-ring-adjoint-model.js';

const modulo = (value: bigint, modulus: bigint) =>
    ((value % modulus) + modulus) % modulus;

describe('structured adjoint for limb-weighted key equations', () => {
    it('matches the independently assembled convolution matrix for every small-field challenge', () => {
        const prime = 97n;
        for (const degree of [2, 4, 8, 16, 32])
            for (const coefficients of [
                Array.from({ length: degree }, (_, index) =>
                    BigInt(13 * index * index - 47 * index + 11),
                ),
                Array.from({ length: degree }, (_, index) =>
                    index === degree - 1 ? -1n : 0n,
                ),
                Array.from({ length: degree }, () => 1n),
            ])
                for (let alpha = 0n; alpha < prime; alpha++) {
                    const powers = [1n];
                    for (let index = 1; index < degree; index++)
                        powers.push((powers[index - 1] * alpha) % prime);
                    const expected = Array.from(
                        { length: degree },
                        (_, input) => {
                            let sum = 0n;
                            for (let output = 0; output < degree; output++) {
                                const coefficient =
                                    (output - input + degree) % degree;
                                sum +=
                                    (output < input ? -1n : 1n) *
                                    coefficients[coefficient] *
                                    powers[output];
                            }
                            return modulo(sum, prime);
                        },
                    );
                    expect(
                        geometricNegacyclicAdjoint(coefficients, alpha, prime),
                    ).toEqual(expected);
                }
    });

    it('commutes limb weighting with the convolution transpose', () => {
        const modulus = 97n,
            radix = 16n,
            degree = 8,
            limbs = 3;
        const coefficients = [-4095n, -257n, -16n, -1n, 0n, 1n, 256n, 4095n];
        for (let alpha = 0n; alpha < modulus; alpha++) {
            const limbWeight = alpha ** BigInt(degree) % modulus;
            const compressed = coefficients.map((value) =>
                fingerprintSignedLimbs(
                    value,
                    radix,
                    limbs,
                    limbWeight,
                    modulus,
                ),
            );
            const actual = geometricNegacyclicAdjoint(
                compressed,
                alpha,
                modulus,
            );
            const expected = Array.from({ length: degree }, () => 0n);
            for (let limb = 0; limb < limbs; limb++) {
                const digits = coefficients.map(
                    (value) =>
                        (value < 0n ? -1n : 1n) *
                        (((value < 0n ? -value : value) /
                            radix ** BigInt(limb)) %
                            radix),
                );
                const component = geometricNegacyclicAdjoint(
                    digits,
                    alpha,
                    modulus,
                );
                for (let index = 0; index < degree; index++)
                    expected[index] = modulo(
                        expected[index] +
                            component[index] * limbWeight ** BigInt(limb),
                        modulus,
                    );
            }
            expect(actual).toEqual(expected);
        }
        expect(() =>
            fingerprintSignedLimbs(4096n, radix, limbs, 3n, modulus),
        ).toThrow('omitted public digits');
    });
});
