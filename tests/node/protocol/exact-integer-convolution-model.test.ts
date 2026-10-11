import { describe, expect, it } from 'vitest';

import { integerLimbConvolutionMagnitudeBound } from '#tests/exact-integer-convolution-model.js';

const convolution = (left: readonly bigint[], right: readonly bigint[]) => {
    const values = left.map(() => 0n);
    for (let first = 0; first < left.length; first++)
        for (let second = 0; second < right.length; second++)
            values[(first + second) % values.length] +=
                (first + second >= values.length ? -1n : 1n) *
                left[first] *
                right[second];
    return values;
};
const centered = (value: bigint, modulus: bigint) => {
    const residue = ((value % modulus) + modulus) % modulus;
    return residue > modulus / 2n ? residue - modulus : residue;
};

describe('exact integer convolution through an auxiliary field', () => {
    it('retains the centered endpoint and rejects its first alias', () => {
        const safe = convolution([4n, 4n, 0n, 0n], [1n, 1n, 0n, 0n]);
        expect(integerLimbConvolutionMagnitudeBound(5n, 2n, 17n)).toBe(8n);
        expect(safe.map((value) => centered(value, 17n))).toEqual(safe);

        const aliased = convolution([3n, 3n, 3n, 0n], [1n, 1n, 1n, 0n]);
        expect(aliased[2]).toBe(9n);
        expect(centered(aliased[2], 17n)).toBe(-8n);
        expect(() => integerLimbConvolutionMagnitudeBound(4n, 3n, 17n)).toThrow(
            'cannot identify',
        );
    });

    it('covers signed digits, negative wraparound, and zero support', () => {
        for (const left of [
            [-15n, 7n, 15n, -1n],
            [15n, 15n, -15n, -15n],
        ])
            for (const right of [
                [1n, 0n, -1n, 0n],
                [0n, -1n, 0n, -1n],
                [0n, 0n, 0n, 0n],
            ]) {
                const norm = right.reduce(
                    (sum, value) => sum + (value < 0n ? -value : value),
                    0n,
                );
                const bound = integerLimbConvolutionMagnitudeBound(
                    16n,
                    norm,
                    97n,
                );
                const exact = convolution(left, right);
                expect(
                    exact.every(
                        (value) => (value < 0n ? -value : value) <= bound,
                    ),
                ).toBe(true);
                expect(exact.map((value) => centered(value, 97n))).toEqual(
                    exact,
                );
            }
    });
});
