import { describe, expect, it } from 'vitest';

import { compileRnsArithmeticResourceCensus } from '#tests/rns-arithmetic-resource-model.js';

describe('exact RNS arithmetic resource floor', () => {
    it('rejects recursively duplicated transform tables before materialization', () => {
        const census = compileRnsArithmeticResourceCensus();
        const layers = Array.from({ length: 30 }, (_, index) =>
            BigInt(index + 1),
        );
        const independentTotal = layers.reduce(
            (sum, count) => sum + count * 4n * 65536n * 8n,
            0n,
        );
        expect(census.multiplicationPrimes).toBe(30n);
        expect(census.recursiveTableBytes).toBe(independentTotal);
        expect(census.recursiveTableBytes).toBeGreaterThan(
            640n * 1024n * 1024n,
        );
        expect(census.exactProductPrimes).toBe(31n);
        expect(census.flatTableBytes).toBe(65011712n);
    });

    it('charges fixed public coefficients and transformed multiplication keys separately', () => {
        const census = compileRnsArithmeticResourceCensus();
        expect(census.coefficientWords).toBe(14n);
        expect(census.canonicalPolynomialBytes).toBe(7340032n);
        expect(census.cachedMultiplicationKeyBytes).toBe(226492416n);
    });
});
