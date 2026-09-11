import { describe, expect, it } from 'vitest';

import {
    compileCommonMatrixSamplingCensus,
    uniformWordResidueDistance,
} from '#tests/common-matrix-sampling-model.js';

describe('fixed-suite public-matrix sampling', () => {
    it('matches independently enumerated residue and conditioned-oracle laws', () => {
        for (let bits = 2; bits <= 12; bits++) {
            const space = 1n << BigInt(bits);
            const maximumModulus = space < 127n ? space : 127n;
            for (let modulus = 2n; modulus <= maximumModulus; modulus++) {
                const counts = Array.from(
                    { length: Number(modulus) },
                    () => 0n,
                );
                for (let word = 0n; word < space; word++)
                    counts[Number(word % modulus)]++;
                const residual = counts.reduce((sum, count) => {
                    const difference = modulus * count - space;
                    return sum + (difference < 0n ? -difference : difference);
                }, 0n);
                const distance = uniformWordResidueDistance(modulus, bits);
                expect(distance.denominator).toBe(modulus * space);
                expect(2n * distance.numerator).toBe(residual);
                // Condition on a uniform residue, then sample a full word
                // uniformly from its actual fiber. Each fiber is nonempty.
                expect(counts.every((count) => count > 0n)).toBe(true);
                const conditionedResidual = counts.reduce((sum, count) => {
                    const difference = space - modulus * count;
                    return sum + (difference < 0n ? -difference : difference);
                }, 0n);
                expect(conditionedResidual).toBe(residual);
            }
        }
    });

    it('covers every common vector and charges the complete sampling expansion', () => {
        const census = compileCommonMatrixSamplingCensus();
        // Six gadget coordinates in each of a, u, and the automorphism vector,
        // plus distinct common polynomials for sharing and auxiliary scores.
        expect(census.fhePolynomialCount).toBe(18n);
        expect(census.coefficientCount).toBe(18n * 65536n + 65536n + 4096n);
        expect(census.expandedSampleBytes).toBe(159907840n);
        expect(census.distanceBits).toBe(141);
        expect(census.distanceUpperNumerator << 141n).toBeLessThanOrEqual(
            census.distanceUpperDenominator,
        );
        expect(census.distanceUpperNumerator << 142n).toBeGreaterThan(
            census.distanceUpperDenominator,
        );
    });

    it('shows why the matrix label cannot be chosen after observing its output', () => {
        const fixed: number[] = [],
            selected: number[] = [];
        for (let first = 0; first < 4; first++)
            for (let second = 0; second < 4; second++) {
                fixed.push(first % 2);
                selected.push(Math.min(first % 2, second % 2));
            }
        expect(fixed.filter((value) => value === 0)).toHaveLength(8);
        expect(selected.filter((value) => value === 0)).toHaveLength(12);
    });

    it('distinguishes an exact division from biased reduction and an undersized word', () => {
        expect(uniformWordResidueDistance(16n, 8).numerator).toBe(0n);
        expect(uniformWordResidueDistance(221n, 8)).toEqual({
            numerator: 6510n,
            denominator: 56576n,
        });
        expect(() => uniformWordResidueDistance(257n, 8)).toThrow(
            'does not cover',
        );
    });
});
