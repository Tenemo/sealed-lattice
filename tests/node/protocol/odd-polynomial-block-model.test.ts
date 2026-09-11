import { describe, expect, it } from 'vitest';

import { evaluateOddPolynomialBlocks } from '#tests/odd-polynomial-block-model.js';

const modulus = 65537n;
const normalize = (value: bigint): bigint =>
    ((value % modulus) + modulus) % modulus;

describe('balanced odd-polynomial blocks', () => {
    it('agrees with Horner evaluation across full, partial, and single-block shapes', () => {
        for (const maximumDegree of [1, 3, 15, 17, 31, 55, 181, 361]) {
            for (const blockWidth of [4, 8, 16, 32, 64]) {
                const coefficients = Array.from(
                    { length: maximumDegree + 1 },
                    (_, exponent) =>
                        exponent % 2 === 0
                            ? 0n
                            : BigInt(
                                  (exponent * exponent + 3 * exponent + 7) %
                                      65537,
                              ),
                );
                for (const variable of [0n, 1n, -1n, 2n, 17n, 32768n, 65536n]) {
                    const actual = evaluateOddPolynomialBlocks(
                        variable,
                        maximumDegree,
                        blockWidth,
                        {
                            add: (left, right) => normalize(left + right),
                            multiply: (left, right) => normalize(left * right),
                            weight: (power, exponent) =>
                                normalize(power * coefficients[exponent]),
                        },
                    );
                    const expected = coefficients.reduceRight(
                        (value, coefficient) =>
                            normalize(value * variable + coefficient),
                        0n,
                    );
                    expect(actual).toBe(expected);
                }
            }
        }
    });

    it('uses the derived comparison multiplication graph', () => {
        let multiplications = 0;
        const depth = evaluateOddPolynomialBlocks(0, 181, 16, {
            add: Math.max,
            multiply: (left, right) => {
                multiplications++;
                return Math.max(left, right) + 1;
            },
            weight: (value) => value,
        });
        // Eleven baby-power products, four giant squares, eleven block merges.
        expect(multiplications).toBe(11 + 4 + 11);
        expect(depth).toBe(8);
    });
});
