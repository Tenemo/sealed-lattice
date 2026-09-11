import { describe, expect, it } from 'vitest';

import {
    splitSaltCollision,
    swapFinalSpongeOutput,
} from '#tests/sponge-reprogramming-path-model.js';

const permutations = (remaining: readonly number[]): number[][] =>
    remaining.length === 0
        ? [[]]
        : remaining.flatMap((value, position) =>
              permutations(
                  remaining.filter((_, index) => index !== position),
              ).map((suffix) => [value, ...suffix]),
          );

describe('direct permutation reprogramming path conditions', () => {
    it('shows that changing a repeated final input can fail to set the intended tag', () => {
        const value = swapFinalSpongeOutput([0, 1, 2, 3], 1, [0, 0], 1);
        expect(value.originalInputs).toEqual([0, 0]);
        expect(value.finalInputOccursInPrefix).toBe(true);
        expect(value.otherInputOccursInPrefix).toBe(false);
        expect(value.changedOutput & 1).toBe(0);
    });

    it('shows the separate failure when the swap partner occurs in the prefix', () => {
        const value = swapFinalSpongeOutput([0, 1, 2, 3], 1, [0, 1], 0);
        expect(value.originalInputs).toEqual([0, 1]);
        expect(value.finalInputOccursInPrefix).toBe(false);
        expect(value.otherInputOccursInPrefix).toBe(true);
        expect(value.changedOutput & 1).toBe(1);
    });

    it('preserves the full target whenever both modified inputs are outside the earlier path', () => {
        const verifiedCases: { actual: number; expected: number }[] = [];
        for (const permutation of permutations([0, 1, 2, 3]))
            for (let length = 1; length <= 3; length++)
                for (let pattern = 0; pattern < 2 ** length; pattern++)
                    for (let target = 0; target < 4; target++) {
                        const blocks = Array.from(
                            { length },
                            (_, index) => (pattern >> index) & 1,
                        );
                        const value = swapFinalSpongeOutput(
                            permutation,
                            1,
                            blocks,
                            target,
                        );
                        expect([...value.changedPermutation].sort()).toEqual([
                            0, 1, 2, 3,
                        ]);
                        if (
                            !value.finalInputOccursInPrefix &&
                            !value.otherInputOccursInPrefix
                        ) {
                            verifiedCases.push({
                                actual: value.changedOutput,
                                expected: target,
                            });
                        }
                    }
        expect(verifiedCases.length).toBeGreaterThan(0);
        expect(verifiedCases.map(({ actual }) => actual)).toEqual(
            verifiedCases.map(({ expected }) => expected),
        );
    });

    it('does not infer full salt entropy from bijectivity of each permutation step', () => {
        const value = splitSaltCollision();
        expect([...value.permutation].sort()).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
        expect(value.outputs).toEqual([0, 2, 2, 0]);
        expect(new Set(value.outputs).size).toBe(2);
    });

    it('refuses malformed permutation and rate inputs', () => {
        expect(() => swapFinalSpongeOutput([0, 0, 1, 2], 1, [0], 1)).toThrow(
            RangeError,
        );
        expect(() => swapFinalSpongeOutput([0, 1, 2, 3], 2, [0], 1)).toThrow(
            RangeError,
        );
        expect(() => swapFinalSpongeOutput([0, 1, 2, 3], 1, [2], 1)).toThrow(
            RangeError,
        );
        expect(() => swapFinalSpongeOutput([0, 1, 2, 3], 1, [], 1)).toThrow(
            RangeError,
        );
    });
});
