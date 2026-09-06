import { describe, expect, it } from 'vitest';

import { compileRecipientKeyUniquenessBound } from '#tests/recipient-key-uniqueness-model.js';

const modulo = (value: number, prime: number): number =>
    ((value % prime) + prime) % prime;

const directCollisions = (prime: number, bound: number): Set<number> => {
    const collisions = new Set<number>();
    for (let a0 = 0; a0 < prime; a0 += 1) {
        for (let a1 = 0; a1 < prime; a1 += 1) {
            const publicKeys = new Set<number>();
            for (let x0 = -bound; x0 <= bound; x0 += 1) {
                for (let x1 = -bound; x1 <= bound; x1 += 1) {
                    for (let e0 = -bound; e0 <= bound; e0 += 1) {
                        for (let e1 = -bound; e1 <= bound; e1 += 1) {
                            const b0 = modulo(-a0 * x0 + a1 * x1 + e0, prime);
                            const b1 = modulo(-a0 * x1 - a1 * x0 + e1, prime);
                            const key = b0 + prime * b1;
                            if (publicKeys.has(key))
                                collisions.add(a0 + prime * a1);
                            publicKeys.add(key);
                        }
                    }
                }
            }
        }
    }
    return collisions;
};

// Independent oracle: use CRT at the two roots of X^2+1 to solve every
// bounded difference equation, including nonunits. No key generation is used.
const differenceCollisions = (
    prime: number,
    root: number,
    bound: number,
): Readonly<{
    collisions: ReadonlySet<number>;
    zeroDivisorDifferenceCount: number;
}> => {
    const inverse = (value: number): number => {
        let result = 1;
        for (let index = 0; index < prime - 2; index += 1)
            result = modulo(result * value, prime);
        return result;
    };
    const solutions = (left: number, right: number): number[] => {
        if (left !== 0) return [modulo(right * inverse(left), prime)];
        return right === 0
            ? Array.from({ length: prime }, (_unused, value) => value)
            : [];
    };
    expect(modulo(root * root, prime)).toBe(prime - 1);
    const collisions = new Set<number>();
    let zeroDivisorDifferenceCount = 0;
    for (let u = -2 * bound; u <= 2 * bound; u += 1) {
        for (let v = -2 * bound; v <= 2 * bound; v += 1) {
            if (u === 0 && v === 0) continue;
            const plus = modulo(u + root * v, prime);
            const minus = modulo(u - root * v, prime);
            if (plus === 0 || minus === 0) zeroDivisorDifferenceCount += 1;
            for (let e0 = -2 * bound; e0 <= 2 * bound; e0 += 1) {
                for (let e1 = -2 * bound; e1 <= 2 * bound; e1 += 1) {
                    const firstSolutions = solutions(
                        plus,
                        modulo(e0 + root * e1, prime),
                    );
                    const secondSolutions = solutions(
                        minus,
                        modulo(e0 - root * e1, prime),
                    );
                    for (const first of firstSolutions)
                        for (const second of secondSolutions) {
                            const a0 = modulo(
                                (first + second) * inverse(2),
                                prime,
                            );
                            const a1 = modulo(
                                (first - second) * inverse(2 * root),
                                prime,
                            );
                            collisions.add(a0 + prime * a1);
                        }
                }
            }
        }
    }
    return { collisions, zeroDivisorDifferenceCount };
};

describe('recipient key uniqueness under uniform common randomness', () => {
    it('matches direct witness collisions with an independent difference-equation oracle', () => {
        const direct = directCollisions(257, 1);
        const difference = differenceCollisions(257, 16, 1);
        expect(direct).toEqual(difference.collisions);
        expect(direct.size).toBe(101);
        expect(direct.has(0)).toBe(true);
        expect(direct.has(10)).toBe(false);
        expect(difference.zeroDivisorDifferenceCount).toBe(0);
    });

    it('includes nonunit differences and does not claim uniqueness for undersized moduli', () => {
        const direct = directCollisions(17, 2);
        const difference = differenceCollisions(17, 4, 2);
        expect(direct).toEqual(difference.collisions);
        // More bounded witnesses than public keys force collisions for every a.
        expect(5 ** 4).toBeGreaterThan(17 ** 2);
        expect(direct.size).toBe(17 ** 2);
        expect(difference.zeroDivisorDifferenceCount).toBeGreaterThan(0);
    });

    it('rounds the full-ring determinant union bound conservatively with exact integers', () => {
        const bound = compileRecipientKeyUniquenessBound();
        // Two difference vectors each have five choices per coefficient;
        // Hadamard contributes 2*sqrt(N) per coefficient before squaring.
        expect(bound.squaredFailureBaseNumerator).toBe(25n ** 2n * 4n * 32768n);
        expect(bound.uniformMatrixFailureExponent).toBe(3_571_712n);
        const exponentPerCoefficient =
            bound.uniformMatrixFailureExponent / bound.polynomialModulusDegree;
        expect(
            bound.squaredFailureBaseNumerator << (2n * exponentPerCoefficient),
        ).toBeLessThanOrEqual(bound.primeModulus ** 2n);
        expect(
            bound.squaredFailureBaseNumerator <<
                (2n * (exponentPerCoefficient + 1n)),
        ).toBeGreaterThan(bound.primeModulus ** 2n);
    });
});
