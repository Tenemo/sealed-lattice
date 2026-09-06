import { describe, expect, it } from 'vitest';

import { subgroupEmbeddingFactor } from '#tests/subgroup-embedding-model.js';

const modulo = (value: bigint, prime: bigint) =>
    ((value % prime) + prime) % prime;
const power = (value: bigint, exponent: bigint, prime: bigint): bigint => {
    let result = 1n;
    for (; exponent > 0n; exponent >>= 1n) {
        if ((exponent & 1n) !== 0n) result = (result * value) % prime;
        value = (value * value) % prime;
    }
    return result;
};
const interpolate = (
    values: readonly bigint[],
    points: readonly bigint[],
    point: bigint,
    prime: bigint,
) => {
    let sum = 0n;
    for (let index = 0; index < values.length; index++) {
        let numerator = 1n,
            denominator = 1n;
        for (let other = 0; other < points.length; other++)
            if (other !== index) {
                numerator = modulo(numerator * (point - points[other]), prime);
                denominator = modulo(
                    denominator * (points[index] - points[other]),
                    prime,
                );
            }
        sum = modulo(
            sum +
                values[index] *
                    numerator *
                    power(denominator, prime - 2n, prime),
            prime,
        );
    }
    return sum;
};

describe('zero embedding into the systematic subgroup', () => {
    it('matches independent full Lagrange interpolation at every field point', () => {
        const prime = 97n,
            size = 16,
            root = 8n;
        expect(power(root, 16n, prime)).toBe(1n);
        expect(power(root, 8n, prime)).not.toBe(1n);
        const points = Array.from({ length: size }, (_, index) =>
            power(root, BigInt(index), prime),
        );
        for (const degree of [1, 2, 4, 8, 16])
            for (const values of [
                Array.from({ length: degree }, (_, index) =>
                    BigInt(13 * index * index - 47 * index + 11),
                ),
                Array.from({ length: degree }, (_, index) =>
                    index === degree - 1 ? 1n : 0n,
                ),
                Array.from({ length: degree }, () => 1n),
            ]) {
                const stride = size / degree;
                const selected = points.filter(
                    (_point, index) => index % stride === 0,
                );
                const embedded = Array.from({ length: size }, (_, index) =>
                    index % stride === 0 ? values[index / stride] : 0n,
                );
                for (let point = 0n; point < prime; point++)
                    expect(
                        (subgroupEmbeddingFactor(point, degree, size, prime) *
                            interpolate(values, selected, point, prime)) %
                            prime,
                    ).toBe(interpolate(embedded, points, point, prime));
            }
    });

    it('rejects a nondividing or empty subgroup', () => {
        expect(() => subgroupEmbeddingFactor(7n, 3, 16, 97n)).toThrow();
        expect(() => subgroupEmbeddingFactor(7n, 0, 16, 97n)).toThrow();
    });
});
