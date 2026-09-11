import { describe, expect, it } from 'vitest';

import {
    compileCommonMatrixSamplingCensus,
    uniformWordResidueDistance,
    boundedResidueFiberWord,
    compileCommonMatrixInitializationCensus,
} from '#tests/common-matrix-sampling-model.js';

describe('fixed-suite public-matrix sampling', () => {
    it('accounts for complete one-pass initialization without a retry budget', () => {
        const matrix = compileCommonMatrixSamplingCensus(),
            initialization = compileCommonMatrixInitializationCensus();
        expect(initialization.programmedPrefixBytes).toBe(
            matrix.expandedSampleBytes,
        );
        expect(initialization.programmedInputs).toBe(
            matrix.fhePolynomialCount + 2n,
        );
        expect(initialization.biasNumerator).toBe(matrix.coefficientCount);
        expect(initialization.biasDenominator).toBe(
            4n << initialization.extraSamplingBits,
        );
        expect(initialization.randomBytes * 8n).toBeGreaterThanOrEqual(
            initialization.randomBits,
        );
        expect(() => boundedResidueFiberWord(3n, 4n, 3n, 0n, 5n)).toThrow();
        expect(() => boundedResidueFiberWord(3n, 4n, 0n, -1n, 5n)).toThrow();
        expect(() => boundedResidueFiberWord(3n, 4n, 0n, 32n, 5n)).toThrow();
    });
    it('samples valid fibers in fixed work and bounds its extra distribution bias', () => {
        const counts = new Map<bigint, bigint>();
        for (let residue = 0n; residue < 5n; residue++)
            for (let random = 0n; random < 32n; random++) {
                const word = boundedResidueFiberWord(
                    5n,
                    4n,
                    residue,
                    random,
                    5n,
                );
                expect(word % 5n).toBe(residue);
                expect(word).toBeLessThan(16n);
                counts.set(word, (counts.get(word) ?? 0n) + 1n);
            }
        const absoluteDifference = [...counts].reduce((sum, [word, count]) => {
            const difference = count * 3n - (word % 5n === 0n ? 24n : 32n);
            return sum + (difference < 0n ? -difference : difference);
        }, 0n);
        // Both laws use denominator 480; half the absolute difference is 1/60.
        expect(absoluteDifference).toBe(16n);
        expect(absoluteDifference * 60n).toBe(2n * 480n);
    });
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
