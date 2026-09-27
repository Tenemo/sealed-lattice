import { describe, expect, it } from 'vitest';

import {
    compileRnsArithmeticResourceCensus,
    researchTransformPrime,
} from '#tests/rns-arithmetic-resource-model.js';
import {
    completionProfile,
    deriveSupportedProfile,
} from '#tests/supported-profile-model.js';

// Deterministic Miller-Rabin with the first twelve prime bases, which is
// exact below 3.3 * 10^24.
const isPrime = (value: bigint): boolean => {
    const bases = [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n];
    if (bases.includes(value)) return true;
    if (value < 2n || value % 2n === 0n) return false;
    let odd = value - 1n,
        twos = 0;
    while (odd % 2n === 0n) {
        odd /= 2n;
        twos++;
    }
    const power = (base: bigint, exponent: bigint) => {
        let result = 1n;
        for (let factor = base % value; exponent > 0n; exponent >>= 1n) {
            if (exponent & 1n) result = (result * factor) % value;
            factor = (factor * factor) % value;
        }
        return result;
    };
    return bases.every((base) => {
        let witness = power(base, odd);
        if (witness === 1n || witness === value - 1n) return true;
        for (let round = 1; round < twos; round++) {
            witness = (witness * witness) % value;
            if (witness === value - 1n) return true;
        }
        return false;
    });
};

describe('exact RNS arithmetic resource floor', () => {
    it('rejects recursively duplicated transform tables before materialization', () => {
        const census = compileRnsArithmeticResourceCensus(completionProfile());
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
        expect(census.flatTableBytesPerPrime).toBe(2n * 65536n * 8n);
        expect(census.flatTableBytes).toBe(31n * 2n * 65536n * 8n);
    });

    it('charges fixed public coefficients and transformed multiplication keys separately', () => {
        const census = compileRnsArithmeticResourceCensus(completionProfile());
        expect(census.coefficientWords).toBe(14n);
        expect(census.canonicalPolynomialBytes).toBe(7340032n);
        expect(census.externalProductPrimes).toBe(18n);
        expect(census.multiplicationKeyRecordBytes).toBe(226492416n);
    });

    it('selects decreasing certified transform primes below 2^58', () => {
        let previous = 1n << 58n;
        for (let index = 0; index < 40; index++) {
            const prime = researchTransformPrime(index);
            expect(prime < previous).toBe(true);
            expect(prime >= 1n << 57n).toBe(true);
            expect((prime - 1n) % (1n << 32n)).toBe(0n);
            expect(((prime - 1n) >> 32n) % 2n).toBe(1n);
            expect(isPrime(prime)).toBe(true);
            previous = prime;
        }
    });

    it('lifts every profile from the fewest primes that exceed its bounds', () => {
        // Bit lengths of the centered bounds: each prime has 58 bits.
        for (const [participantCount, optionCount, gadgetLength] of [
            [3, 2, 4n],
            [10, 10, 6n],
            [20, 20, 7n],
        ] as const) {
            const profile = deriveSupportedProfile(
                participantCount,
                optionCount,
            );
            const census = compileRnsArithmeticResourceCensus(profile);
            expect(profile.gadgetLength).toBe(gadgetLength);
            const half = profile.ciphertext.modulus / 2n;
            for (const [count, bound] of [
                [census.exactProductPrimes, 2n * 65536n * half * half],
                [
                    census.externalProductPrimes,
                    2n * gadgetLength * 65536n * ((1n << 144n) - 1n) * half,
                ],
            ] as const) {
                let product = 1n;
                for (let index = 0; index < Number(count) - 1; index++)
                    product *= researchTransformPrime(index);
                expect(product <= bound).toBe(true);
                expect(
                    product * researchTransformPrime(Number(count) - 1) > bound,
                ).toBe(true);
                const bits = BigInt(bound.toString(2).length);
                expect(count >= (bits + 57n) / 58n).toBe(true);
                expect(count <= bits / 57n + 1n).toBe(true);
            }
            expect(census.multiplicationKeyRecordBytes).toBe(
                4n * gadgetLength * census.externalProductPrimes * 65536n * 8n,
            );
        }
    });
});
